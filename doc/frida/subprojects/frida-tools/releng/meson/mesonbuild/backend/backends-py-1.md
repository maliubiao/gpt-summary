Response:
Let's break down the thought process for analyzing this Python code snippet. The goal is to understand its function, relate it to reverse engineering, low-level aspects, infer logic, identify potential errors, and trace user interaction.

**1. Initial Skim and Keywords:**

First, I'd quickly read through the code, looking for familiar keywords and patterns. Terms like `rpath`, `shared_libraries`, `link_args`, `compiler`, `object_filename`, `PCH`, `debug`, `test`, `benchmark`, `install`, `cross_build`, `windows`, `linux`, and file system operations (`os.path`, `Path`) immediately jump out. These keywords give strong hints about the code's purpose.

**2. High-Level Function Identification (The "What"):**

Based on the keywords, I can start forming a high-level idea of what the code does. It seems to be involved in the build process of software, specifically focusing on:

* **Handling shared libraries and their dependencies:**  The `rpaths_for_non_system_absolute_shared_libraries` function is a clear indicator of this. RPATHs are crucial for runtime linking of shared libraries.
* **Compiler argument generation:**  Functions like `generate_basic_compiler_args` suggest this.
* **Object file naming:**  `object_filename_from_source` clearly deals with this.
* **Precompiled headers (PCH):** The presence of `get_pch_include_args` and `create_msvc_pch_implementation` points to PCH handling.
* **Testing and benchmarking:**  The `write_test_file`, `write_benchmark_file`, and related functions confirm this.
* **Installation:** `generate_depmf_install` indicates handling installation artifacts.
* **Cross-compilation:**  The frequent checks for `target.for_machine` and mentions of Windows and MinGW suggest cross-compilation support.

**3. Deeper Dive into Specific Functions:**

Next, I'd examine individual functions more closely to understand their specific roles. For instance:

* **`rpaths_for_non_system_absolute_shared_libraries`:**  This function seems to determine the runtime library search paths (RPATHs) needed for a target. It iterates through dependencies, checks for absolute paths to libraries, and adds those directories to the RPATH. The exclusion of system paths and handling of Windows (which doesn't use RPATHs directly) are interesting details.
* **`object_filename_from_source`:** This function generates the name of the object file based on the source file. It handles generated sources, absolute paths, and platform-specific object suffixes. The Vala-specific logic is noteworthy.
* **`generate_basic_compiler_args`:** This function builds up the command-line arguments for the compiler, considering various factors like optimization level, debug flags, include paths, and dependency information. The order of adding arguments is important.
* **`determine_windows_extra_paths`:** This function addresses the lack of RPATHs on Windows by finding the directories containing the necessary DLLs. It looks at dependencies and common locations like `bin` directories.
* **`create_test_serialisation`:** This function prepares test information for serialization, including the executable path, command-line arguments, environment variables, and dependencies. The handling of cross-compilation and Windows-specific paths is evident.

**4. Connecting to Reverse Engineering, Low-Level, and Kernel/Framework:**

Now, I can start linking these functions to the requested concepts:

* **Reverse Engineering:** RPATHs are directly relevant to reverse engineering because they determine where the dynamic linker searches for shared libraries at runtime. Understanding the RPATHs can help an analyst understand the dependency structure of a binary. The Windows DLL path handling serves a similar purpose. Frida itself is a reverse engineering tool, so this backend is crucial for building Frida's components.
* **Binary Low-Level:**  The code deals with object files, linking, and compiler flags, all of which are fundamental to binary-level operations. The PCH logic optimizes compilation, a low-level concern. The handling of different file extensions (`.so`, `.dll`, `.lib`) and platform-specific linking mechanisms highlights the binary-level nature.
* **Linux/Android Kernel & Framework:**  RPATHs are a Linux concept. The environment variable `LD_LIBRARY_PATH` is specific to Linux. While Android isn't explicitly mentioned in this *snippet*, the concepts of shared libraries and dynamic linking are shared. The handling of `.so` files strongly implies Linux-like systems.

**5. Logical Inference and Example:**

Let's take `rpaths_for_non_system_absolute_shared_libraries` and create a hypothetical scenario:

* **Input:** A `BuildTarget` representing an executable that links against a shared library located at `/opt/mylib/libfoo.so`. The source code is in `/home/user/myproject`.
* **Assumption:**  `/opt/mylib` is not a system library directory.
* **Output:** The function would likely add `/opt/mylib` to the list of RPATH directories. If the library were in a subdirectory of the source directory, like `/home/user/myproject/external/libfoo.so`, the output would be `../external`.

**6. User/Programming Errors:**

* **Incorrect `--just-symbols` usage:** The code explicitly checks for directory paths with `--just-symbols`, preventing a common misconfiguration.
* **Missing DLLs on Windows:** The `determine_windows_extra_paths` function addresses a potential runtime error where the program can't find the necessary DLLs.
* **Clock skew:** The `check_clock_skew` function prevents a frustrating build loop caused by incorrect system time.

**7. Tracing User Operations:**

To reach this code, a user would likely be in the process of building a Frida component using Meson. The steps would involve:

1. **Running `meson`:**  This initiates the build system configuration.
2. **Meson parsing `meson.build`:** Meson reads the build definition files.
3. **Defining targets and dependencies:** The `meson.build` files would define the build targets (executables, libraries) and their dependencies.
4. **Generating build files:** Meson generates the necessary build files for the chosen backend (e.g., Ninja).
5. **Running the build tool (e.g., `ninja`):**  The build tool executes the build commands.
6. **During linking:** When linking an executable or shared library, Meson (through this backend code) would determine the necessary RPATHs or DLL search paths.
7. **Running tests/benchmarks:**  If tests or benchmarks are defined, Meson would use the functions in this file to prepare and execute them.

**8. Summarization (The "Gist"):**

Finally, I'd synthesize the findings into a concise summary: This code snippet is a crucial part of Frida's build system, responsible for generating platform-specific build configurations, particularly concerning shared library linking (RPATHs on Linux, DLL paths on Windows), compiler arguments, object file naming, precompiled header handling, and the execution of tests and benchmarks. It bridges the gap between the high-level build definition and the low-level details of compilation and linking, taking into account cross-compilation scenarios.

This systematic approach, starting with a high-level overview and gradually drilling down into specifics, helps in understanding complex code like this and relating it to the requested concepts.
这是 `frida/subprojects/frida-tools/releng/meson/mesonbuild/backend/backends.py` 文件的第 2 部分，主要负责生成特定于后端的构建系统所需的各种文件和配置信息，以便实际执行编译、链接和安装等操作。它涵盖了与编译器、链接器、测试和安装相关的多个方面。

以下是该部分代码的功能归纳：

**核心功能：处理编译和链接过程中的细节，特别是与共享库依赖和路径相关的问题。**

**具体功能点：**

1. **确定和管理运行时库搜索路径 (RPATHs)：**
   - `get_external_rpath_dirs`: 从目标文件的链接参数中提取显式指定的 RPATH 目录。
   - `get_rpath_dirs_from_link_args`:  从链接参数中提取 RPATH 目录。
   - `rpaths_for_non_system_absolute_shared_libraries`: 针对非系统绝对路径的共享库，确定需要添加的 RPATH 目录。这对于确保程序运行时能找到依赖的共享库非常重要。
   - `determine_rpath_dirs`:  综合考虑各种因素，最终确定目标文件需要的 RPATH 目录列表。

2. **生成对象文件名：**
   - `canonicalize_filename`:  规范化文件名，避免特殊字符导致的问题。
   - `object_filename_from_source`: 根据源文件路径生成对应的对象文件名。这涉及到处理各种情况，例如 Vala 语言的编译、生成的源文件以及绝对路径的源文件。

3. **处理提取的对象文件：**
   - `_determine_ext_objs`:  处理从静态库或对象文件中提取出来的对象文件，用于链接到其他目标。

4. **处理预编译头文件 (PCH)：**
   - `get_pch_include_args`:  生成使用预编译头文件所需的编译器参数。
   - `get_msvc_pch_objname`: 获取 MSVC 编译器预编译头文件的对象文件名。
   - `create_msvc_pch_implementation`:  创建 MSVC 编译器预编译头文件的实现文件。
   - `target_uses_pch`:  检查目标是否使用了预编译头文件。

5. **生成基本的编译器参数：**
   - `escape_extra_args`:  转义额外的编译器参数，例如处理定义中的反斜杠。
   - `get_no_stdlib_args`:  获取禁用标准库包含路径的编译器参数。
   - `generate_basic_compiler_args`: 生成基本的编译器参数列表，包括优化级别、调试信息、包含路径等。

6. **处理链接参数：**
   - `build_target_link_arguments`:  生成链接目标文件所需的链接器参数。

7. **处理 Windows 平台特定的路径问题：**
   - `get_mingw_extra_paths`: 获取 MinGW 环境下额外的程序和库路径。
   - `search_dll_path`:  在 Windows 上搜索 DLL 文件的路径，因为 Windows 没有 RPATH 机制。
   - `extract_dll_paths`:  提取目标文件依赖的所有 DLL 文件的路径。
   - `determine_windows_extra_paths`:  确定 Windows 平台上需要添加的额外路径，以便程序运行时能找到依赖的 DLL 文件。

8. **生成测试和基准测试文件：**
   - `write_benchmark_file`:  将基准测试信息写入文件。
   - `write_test_file`:  将测试信息写入文件。
   - `create_test_serialisation`:  将测试信息序列化为可供测试运行器使用的格式。
   - `write_test_serialisation`: 将序列化后的测试信息写入文件。
   - `construct_target_rel_paths`:  构建目标文件的相对路径，用于测试命令。

9. **生成依赖清单文件：**
   - `generate_depmf_install`: 生成依赖清单安装信息。

10. **处理构建定义文件的更改：**
    - `get_regen_filelist`: 获取所有需要监控的文件列表，当这些文件发生更改时，需要重新生成构建定义。
    - `generate_regen_info`: 生成用于检测构建定义文件是否需要重新生成的元数据。
    - `check_clock_skew`: 检查可能导致无限重新配置循环的时钟偏差问题。

11. **其他实用工具函数：**
    - `build_target_to_cmd_array`: 将构建目标转换为命令行数组。
    - `replace_extra_args`: 替换命令中的 `@EXTRA_ARGS@` 占位符。
    - `replace_outputs`: 替换命令中的 `@OUTPUTx@` 占位符。
    - `get_build_by_default_targets`: 获取默认需要构建的目标。
    - `get_testlike_targets`: 获取类似测试的目标（包括测试和基准测试）。

**与逆向的关系及举例：**

* **RPATH 的作用：**  在逆向工程中，理解目标程序依赖哪些共享库以及这些库的加载路径至关重要。`rpaths_for_non_system_absolute_shared_libraries` 函数生成的 RPATH 信息直接影响程序运行时的库查找行为。逆向工程师可以通过分析目标二进制文件的 RPATH 段来了解其依赖关系。例如，如果一个 Frida 插件依赖于自定义的共享库，该函数会确保 Frida 运行时能找到这个库。
* **Windows DLL 路径：**  在 Windows 平台，由于没有 RPATH，理解 `determine_windows_extra_paths` 如何工作有助于逆向工程师理解程序运行时加载 DLL 的机制。Frida 需要确保其依赖的 DLL (例如 frida-core) 能被找到。
* **测试和基准测试：**  Frida 的测试套件会使用 `write_test_file` 等函数生成的信息来验证 Frida 的功能是否正常。逆向工程师在开发 Frida 组件或进行调试时，可以参考这些测试用例来理解 Frida 的预期行为。

**涉及的二进制底层、Linux、Android 内核及框架知识举例：**

* **二进制底层：**  对象文件的生成 (`object_filename_from_source`)、链接参数的处理 (`build_target_link_arguments`) 以及 RPATH 的概念都是与二进制文件结构和链接过程紧密相关的底层知识。
* **Linux：**  RPATH 是一种 Linux 特有的动态链接机制。`rpaths_for_non_system_absolute_shared_libraries` 函数的实现体现了对 Linux 动态链接器行为的理解。环境变量 `LD_LIBRARY_PATH` 的使用也是 Linux 平台的特性。
* **Android 内核及框架：** 虽然代码中没有直接提及 Android 内核，但 Android 系统也使用了类似的动态链接机制（尽管可能有所不同）。Frida 在 Android 上的运行也需要处理共享库的加载问题，尽管具体的实现细节可能在其他部分的代码中。

**逻辑推理的假设输入与输出举例：**

假设有一个名为 `my_library` 的共享库，其路径为 `/opt/custom_libs/libmy_library.so`，并且有一个名为 `my_program` 的可执行文件依赖于它。

* **输入 (传递给 `rpaths_for_non_system_absolute_shared_libraries`):**
    - `target`: 代表 `my_program` 的 `build.BuildTarget` 对象。
    - `target.external_deps`: 包含一个代表 `/opt/custom_libs/libmy_library.so` 的外部依赖对象。

* **输出:**  `rpaths_for_non_system_absolute_shared_libraries` 函数会返回一个包含字符串 `/opt/custom_libs` 的列表，作为 `my_program` 的 RPATH 目录。这意味着在构建 `my_program` 时，构建系统会添加链接器参数，使得 `my_program` 运行时会在 `/opt/custom_libs` 目录下查找 `libmy_library.so`。

**用户或编程常见的使用错误举例：**

* **错误的 `--just-symbols` 用法:** 用户可能错误地将目录路径作为 `--just-symbols` 的参数，导致 `get_external_rpath_dirs` 函数抛出 `MesonException`。这表明用户可能误解了这个选项的用途，该选项应该用于指定符号文件的路径。
* **Windows 上缺少 DLL:**  如果用户在 Windows 上构建依赖于外部 DLL 的程序，但这些 DLL 不在系统的 PATH 环境变量中，也没有被 `determine_windows_extra_paths` 正确识别，那么程序运行时会因为找不到 DLL 而失败。这是一种常见的使用错误，需要用户手动将 DLL 复制到合适的位置或配置环境变量。

**用户操作如何一步步到达这里作为调试线索：**

1. **用户执行 `meson setup builddir`:** 这会初始化 Meson 构建系统，并读取 `meson.build` 文件。
2. **Meson 解析 `meson.build`:**  Meson 会分析项目中的构建目标和依赖关系。如果 `meson.build` 中定义了一个可执行文件或共享库，并且该目标依赖于其他的共享库，那么相关的 `build.BuildTarget` 对象会被创建。
3. **用户执行 `ninja` 或其他构建命令:** 构建工具开始执行实际的编译和链接操作。
4. **链接阶段:** 当链接器处理一个可执行文件或共享库时，Meson 的 backend 代码会被调用。
5. **调用 `rpaths_for_non_system_absolute_shared_libraries`:**  如果被链接的目标依赖于外部的共享库，并且这些库的路径不是系统路径，那么这个函数会被调用来确定需要添加的 RPATH。
6. **调试线索:** 如果用户在运行时遇到 "找不到共享库" 的错误，那么可以检查 `rpaths_for_non_system_absolute_shared_libraries` 函数的输出，查看是否正确地添加了依赖库的路径。在 Windows 上，可以检查 `determine_windows_extra_paths` 的输出，看是否遗漏了某些 DLL 的路径。

**该部分的功能归纳：**

该部分代码的核心功能是 **处理软件构建过程中与依赖库链接相关的细节，并生成相应的构建系统配置**。它专注于解决以下问题：

* **确保程序运行时能够找到依赖的共享库 (通过 RPATH 或 Windows 的 DLL 搜索路径)。**
* **生成正确的编译器和链接器参数，包括处理预编译头文件。**
* **生成用于测试和基准测试的元数据。**
* **处理跨平台构建中的特定问题 (例如 Windows 的 DLL 路径)。**
* **监控构建定义文件的更改，以便在必要时重新生成构建系统。**

总而言之，这部分代码是 Frida 构建系统的关键组成部分，它将高层次的构建描述转换为底层构建工具能够理解的指令，特别是在处理共享库依赖方面扮演着至关重要的角色。

### 提示词
```
这是目录为frida/subprojects/frida-tools/releng/meson/mesonbuild/backend/backends.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```python
if Path(dir).is_dir():
                        dirs.add(dir)
            symbols_match = symbols_regex.match(arg)
            if symbols_match:
                for dir in symbols_match.group(1).split(':'):
                    # Prevent usage of --just-symbols to specify rpath
                    if Path(dir).is_dir():
                        raise MesonException(f'Invalid arg for --just-symbols, {dir} is a directory.')
        return dirs

    @lru_cache(maxsize=None)
    def rpaths_for_non_system_absolute_shared_libraries(self, target: build.BuildTarget, exclude_system: bool = True) -> 'ImmutableListProtocol[str]':
        paths: OrderedSet[str] = OrderedSet()
        srcdir = self.environment.get_source_dir()

        for dep in target.external_deps:
            if dep.type_name not in {'library', 'pkgconfig', 'cmake'}:
                continue
            for libpath in dep.link_args:
                # For all link args that are absolute paths to a library file, add RPATH args
                if not os.path.isabs(libpath):
                    continue
                libdir = os.path.dirname(libpath)
                if exclude_system and self._libdir_is_system(libdir, target.compilers, self.environment):
                    # No point in adding system paths.
                    continue
                # Don't remove rpaths specified in LDFLAGS.
                if libdir in self.get_external_rpath_dirs(target):
                    continue
                # Windows doesn't support rpaths, but we use this function to
                # emulate rpaths by setting PATH
                # .dll is there for mingw gcc
                # .so's may be extended with version information, e.g. libxyz.so.1.2.3
                if not (
                    os.path.splitext(libpath)[1] in {'.dll', '.lib', '.so', '.dylib'}
                    or re.match(r'.+\.so(\.|$)', os.path.basename(libpath))
                ):
                    continue

                try:
                    commonpath = os.path.commonpath((libdir, srcdir))
                except ValueError: # when paths are on different drives on Windows
                    commonpath = ''

                if commonpath == srcdir:
                    rel_to_src = libdir[len(srcdir) + 1:]
                    assert not os.path.isabs(rel_to_src), f'rel_to_src: {rel_to_src} is absolute'
                    paths.add(os.path.join(self.build_to_src, rel_to_src))
                else:
                    paths.add(libdir)
            # Don't remove rpaths specified by the dependency
            paths.difference_update(self.get_rpath_dirs_from_link_args(dep.link_args))
        for i in chain(target.link_targets, target.link_whole_targets):
            if isinstance(i, build.BuildTarget):
                paths.update(self.rpaths_for_non_system_absolute_shared_libraries(i, exclude_system))
        return list(paths)

    # This may take other types
    def determine_rpath_dirs(self, target: T.Union[build.BuildTarget, build.CustomTarget, build.CustomTargetIndex]
                             ) -> T.Tuple[str, ...]:
        result: OrderedSet[str]
        if self.environment.coredata.get_option(OptionKey('layout')) == 'mirror':
            # Need a copy here
            result = OrderedSet(target.get_link_dep_subdirs())
        else:
            result = OrderedSet()
            result.add('meson-out')
        if isinstance(target, build.BuildTarget):
            result.update(self.rpaths_for_non_system_absolute_shared_libraries(target))
            target.rpath_dirs_to_remove.update([d.encode('utf-8') for d in result])
        return tuple(result)

    @staticmethod
    def canonicalize_filename(fname: str) -> str:
        parts = Path(fname).parts
        hashed = ''
        if len(parts) > 5:
            temp = '/'.join(parts[-5:])
            # is it shorter to hash the beginning of the path?
            if len(fname) > len(temp) + 41:
                hashed = hashlib.sha1(fname.encode('utf-8')).hexdigest() + '_'
                fname = temp
        for ch in ('/', '\\', ':'):
            fname = fname.replace(ch, '_')
        return hashed + fname

    def object_filename_from_source(self, target: build.BuildTarget, source: 'FileOrString', targetdir: T.Optional[str] = None) -> str:
        assert isinstance(source, mesonlib.File)
        if isinstance(target, build.CompileTarget):
            return target.sources_map[source]
        build_dir = self.environment.get_build_dir()
        rel_src = source.rel_to_builddir(self.build_to_src)

        # foo.vala files compile down to foo.c and then foo.c.o, not foo.vala.o
        if rel_src.endswith(('.vala', '.gs')):
            # See description in generate_vala_compile for this logic.
            if source.is_built:
                if os.path.isabs(rel_src):
                    rel_src = rel_src[len(build_dir) + 1:]
                rel_src = os.path.relpath(rel_src, self.get_target_private_dir(target))
            else:
                rel_src = os.path.basename(rel_src)
            # A meson- prefixed directory is reserved; hopefully no-one creates a file name with such a weird prefix.
            gen_source = 'meson-generated_' + rel_src[:-5] + '.c'
        elif source.is_built:
            if os.path.isabs(rel_src):
                rel_src = rel_src[len(build_dir) + 1:]
            # A meson- prefixed directory is reserved; hopefully no-one creates a file name with such a weird prefix.
            gen_source = 'meson-generated_' + os.path.relpath(rel_src, self.get_target_private_dir(target))
        else:
            if os.path.isabs(rel_src):
                # Use the absolute path directly to avoid file name conflicts
                gen_source = rel_src
            else:
                gen_source = os.path.relpath(os.path.join(build_dir, rel_src),
                                             os.path.join(self.environment.get_source_dir(), target.get_source_subdir()))
        machine = self.environment.machines[target.for_machine]
        ret = self.canonicalize_filename(gen_source) + '.' + machine.get_object_suffix()
        if targetdir is not None:
            return os.path.join(targetdir, ret)
        return ret

    def _determine_ext_objs(self, extobj: 'build.ExtractedObjects', proj_dir_to_build_root: str) -> T.List[str]:
        result: T.List[str] = []

        targetdir = self.get_target_private_dir(extobj.target)

        # Merge sources and generated sources
        raw_sources = list(extobj.srclist)
        for gensrc in extobj.genlist:
            for r in gensrc.get_outputs():
                path = self.get_target_generated_dir(extobj.target, gensrc, r)
                dirpart, fnamepart = os.path.split(path)
                raw_sources.append(File(True, dirpart, fnamepart))

        # Filter out headers and all non-source files
        sources: T.List['FileOrString'] = []
        for s in raw_sources:
            if self.environment.is_source(s):
                sources.append(s)
            elif self.environment.is_object(s):
                result.append(s.relative_name())

        # MSVC generate an object file for PCH
        if extobj.pch and self.target_uses_pch(extobj.target):
            for lang, pch in extobj.target.pch.items():
                compiler = extobj.target.compilers[lang]
                if compiler.get_argument_syntax() == 'msvc':
                    objname = self.get_msvc_pch_objname(lang, pch)
                    result.append(os.path.join(proj_dir_to_build_root, targetdir, objname))

        # extobj could contain only objects and no sources
        if not sources:
            return result

        # With unity builds, sources don't map directly to objects,
        # we only support extracting all the objects in this mode,
        # so just return all object files.
        if extobj.target.is_unity:
            compsrcs = classify_unity_sources(extobj.target.compilers.values(), sources)
            sources = []
            unity_size = extobj.target.get_option(OptionKey('unity_size'))
            assert isinstance(unity_size, int), 'for mypy'

            for comp, srcs in compsrcs.items():
                if comp.language in LANGS_CANT_UNITY:
                    sources += srcs
                    continue
                for i in range((len(srcs) + unity_size - 1) // unity_size):
                    _src = self.get_unity_source_file(extobj.target,
                                                      comp.get_default_suffix(), i)
                    sources.append(_src)

        for osrc in sources:
            objname = self.object_filename_from_source(extobj.target, osrc, targetdir)
            objpath = os.path.join(proj_dir_to_build_root, objname)
            result.append(objpath)

        return result

    def get_pch_include_args(self, compiler: 'Compiler', target: build.BuildTarget) -> T.List[str]:
        args: T.List[str] = []
        pchpath = self.get_target_private_dir(target)
        includeargs = compiler.get_include_args(pchpath, False)
        p = target.get_pch(compiler.get_language())
        if p:
            args += compiler.get_pch_use_args(pchpath, p[0])
        return includeargs + args

    def get_msvc_pch_objname(self, lang: str, pch: T.List[str]) -> str:
        if len(pch) == 1:
            # Same name as in create_msvc_pch_implementation() below.
            return f'meson_pch-{lang}.obj'
        return os.path.splitext(pch[1])[0] + '.obj'

    def create_msvc_pch_implementation(self, target: build.BuildTarget, lang: str, pch_header: str) -> str:
        # We have to include the language in the file name, otherwise
        # pch.c and pch.cpp will both end up as pch.obj in VS backends.
        impl_name = f'meson_pch-{lang}.{lang}'
        pch_rel_to_build = os.path.join(self.get_target_private_dir(target), impl_name)
        # Make sure to prepend the build dir, since the working directory is
        # not defined. Otherwise, we might create the file in the wrong path.
        pch_file = os.path.join(self.build_dir, pch_rel_to_build)
        os.makedirs(os.path.dirname(pch_file), exist_ok=True)

        content = f'#include "{os.path.basename(pch_header)}"'
        pch_file_tmp = pch_file + '.tmp'
        with open(pch_file_tmp, 'w', encoding='utf-8') as f:
            f.write(content)
        mesonlib.replace_if_different(pch_file, pch_file_tmp)
        return pch_rel_to_build

    def target_uses_pch(self, target: build.BuildTarget) -> bool:
        try:
            return T.cast('bool', target.get_option(OptionKey('b_pch')))
        except KeyError:
            return False

    @staticmethod
    def escape_extra_args(args: T.List[str]) -> T.List[str]:
        # all backslashes in defines are doubly-escaped
        extra_args: T.List[str] = []
        for arg in args:
            if arg.startswith(('-D', '/D')):
                arg = arg.replace('\\', '\\\\')
            extra_args.append(arg)

        return extra_args

    def get_no_stdlib_args(self, target: 'build.BuildTarget', compiler: 'Compiler') -> T.List[str]:
        if compiler.language in self.build.stdlibs[target.for_machine]:
            return compiler.get_no_stdinc_args()
        return []

    def generate_basic_compiler_args(self, target: build.BuildTarget, compiler: 'Compiler') -> 'CompilerArgs':
        # Create an empty commands list, and start adding arguments from
        # various sources in the order in which they must override each other
        # starting from hard-coded defaults followed by build options and so on.
        commands = compiler.compiler_args()

        copt_proxy = target.get_options()
        # First, the trivial ones that are impossible to override.
        #
        # Add -nostdinc/-nostdinc++ if needed; can't be overridden
        commands += self.get_no_stdlib_args(target, compiler)
        # Add things like /NOLOGO or -pipe; usually can't be overridden
        commands += compiler.get_always_args()
        # warning_level is a string, but mypy can't determine that
        commands += compiler.get_warn_args(T.cast('str', target.get_option(OptionKey('warning_level'))))
        # Add -Werror if werror=true is set in the build options set on the
        # command-line or default_options inside project(). This only sets the
        # action to be done for warnings if/when they are emitted, so it's ok
        # to set it after or get_warn_args().
        if target.get_option(OptionKey('werror')):
            commands += compiler.get_werror_args()
        # Add compile args for c_* or cpp_* build options set on the
        # command-line or default_options inside project().
        commands += compiler.get_option_compile_args(copt_proxy)

        optimization = target.get_option(OptionKey('optimization'))
        assert isinstance(optimization, str), 'for mypy'
        commands += compiler.get_optimization_args(optimization)

        debug = target.get_option(OptionKey('debug'))
        assert isinstance(debug, bool), 'for mypy'
        commands += compiler.get_debug_args(debug)

        # Add compile args added using add_project_arguments()
        commands += self.build.get_project_args(compiler, target.subproject, target.for_machine)
        # Add compile args added using add_global_arguments()
        # These override per-project arguments
        commands += self.build.get_global_args(compiler, target.for_machine)
        # Compile args added from the env: CFLAGS/CXXFLAGS, etc, or the cross
        # file. We want these to override all the defaults, but not the
        # per-target compile args.
        commands += self.environment.coredata.get_external_args(target.for_machine, compiler.get_language())
        # Using both /Z7 or /ZI and /Zi at the same times produces a compiler warning.
        # We do not add /Z7 or /ZI by default. If it is being used it is because the user has explicitly enabled it.
        # /Zi needs to be removed in that case to avoid cl's warning to that effect (D9025 : overriding '/Zi' with '/ZI')
        if ('/Zi' in commands) and (('/ZI' in commands) or ('/Z7' in commands)):
            commands.remove('/Zi')
        # Always set -fPIC for shared libraries
        if isinstance(target, build.SharedLibrary):
            commands += compiler.get_pic_args()
        # Set -fPIC for static libraries by default unless explicitly disabled
        if isinstance(target, build.StaticLibrary) and target.pic:
            commands += compiler.get_pic_args()
        elif isinstance(target, (build.StaticLibrary, build.Executable)) and target.pie:
            commands += compiler.get_pie_args()
        # Add compile args needed to find external dependencies. Link args are
        # added while generating the link command.
        # NOTE: We must preserve the order in which external deps are
        # specified, so we reverse the list before iterating over it.
        for dep in reversed(target.get_external_deps()):
            if not dep.found():
                continue

            if compiler.language == 'vala':
                if dep.type_name == 'pkgconfig':
                    assert isinstance(dep, dependencies.ExternalDependency)
                    if dep.name == 'glib-2.0' and dep.version_reqs is not None:
                        for req in dep.version_reqs:
                            if req.startswith(('>=', '==')):
                                commands += ['--target-glib', req[2:].lstrip()]
                                break
                    commands += ['--pkg', dep.name]
                elif isinstance(dep, dependencies.ExternalLibrary):
                    commands += dep.get_link_args('vala')
            else:
                commands += compiler.get_dependency_compile_args(dep)
            # Qt needs -fPIC for executables
            # XXX: We should move to -fPIC for all executables
            if isinstance(target, build.Executable):
                commands += dep.get_exe_args(compiler)
            # For 'automagic' deps: Boost and GTest. Also dependency('threads').
            # pkg-config puts the thread flags itself via `Cflags:`
        # Fortran requires extra include directives.
        if compiler.language == 'fortran':
            for lt in chain(target.link_targets, target.link_whole_targets):
                priv_dir = self.get_target_private_dir(lt)
                commands += compiler.get_include_args(priv_dir, False)
        return commands

    def build_target_link_arguments(self, compiler: 'Compiler', deps: T.List[build.Target]) -> T.List[str]:
        args: T.List[str] = []
        for d in deps:
            if not d.is_linkable_target():
                raise RuntimeError(f'Tried to link with a non-library target "{d.get_basename()}".')
            arg = self.get_target_filename_for_linking(d)
            if not arg:
                continue
            if compiler.get_language() == 'd':
                arg = '-Wl,' + arg
            else:
                arg = compiler.get_linker_lib_prefix() + arg
            args.append(arg)
        return args

    def get_mingw_extra_paths(self, target: build.BuildTarget) -> T.List[str]:
        paths: OrderedSet[str] = OrderedSet()
        # The cross bindir
        root = self.environment.properties[target.for_machine].get_root()
        if root:
            paths.add(os.path.join(root, 'bin'))
        # The toolchain bindir
        sys_root = self.environment.properties[target.for_machine].get_sys_root()
        if sys_root:
            paths.add(os.path.join(sys_root, 'bin'))
        # Get program and library dirs from all target compilers
        if isinstance(target, build.BuildTarget):
            for cc in target.compilers.values():
                paths.update(cc.get_program_dirs(self.environment))
                paths.update(cc.get_library_dirs(self.environment))
        return list(paths)

    @staticmethod
    @lru_cache(maxsize=None)
    def search_dll_path(link_arg: str) -> T.Optional[str]:
        if link_arg.startswith(('-l', '-L')):
            link_arg = link_arg[2:]

        p = Path(link_arg)
        if not p.is_absolute():
            return None

        try:
            p = p.resolve(strict=True)
        except FileNotFoundError:
            return None

        for f in p.parent.glob('*.dll'):
            # path contains dlls
            return str(p.parent)

        if p.is_file():
            p = p.parent
        # Heuristic: replace *last* occurence of '/lib'
        binpath = Path('/bin'.join(p.as_posix().rsplit('/lib', maxsplit=1)))
        for _ in binpath.glob('*.dll'):
            return str(binpath)

        return None

    @classmethod
    @lru_cache(maxsize=None)
    def extract_dll_paths(cls, target: build.BuildTarget) -> T.Set[str]:
        """Find paths to all DLLs needed for a given target, since
        we link against import libs, and we don't know the actual
        path of the DLLs.

        1. If there are DLLs in the same directory than the .lib dir, use it
        2. If there is a sibbling directory named 'bin' with DLLs in it, use it
        """
        results = set()
        for dep in target.external_deps:

            if dep.type_name == 'pkgconfig':
                # If by chance pkg-config knows the bin dir...
                bindir = dep.get_variable(pkgconfig='bindir', default_value='')
                if bindir:
                    results.add(bindir)
                    continue

            results.update(filter(None, map(cls.search_dll_path, dep.link_args)))  # pylint: disable=bad-builtin

        for i in chain(target.link_targets, target.link_whole_targets):
            if isinstance(i, build.BuildTarget):
                results.update(cls.extract_dll_paths(i))

        return results

    def determine_windows_extra_paths(
            self, target: T.Union[build.BuildTarget, build.CustomTarget, build.CustomTargetIndex, programs.ExternalProgram, mesonlib.File, str],
            extra_bdeps: T.Sequence[T.Union[build.BuildTarget, build.CustomTarget]]) -> T.List[str]:
        """On Windows there is no such thing as an rpath.

        We must determine all locations of DLLs that this exe
        links to and return them so they can be used in unit
        tests.
        """
        result: T.Set[str] = set()
        prospectives: T.Set[build.BuildTargetTypes] = set()
        if isinstance(target, build.BuildTarget):
            prospectives.update(target.get_transitive_link_deps())
            # External deps
            result.update(self.extract_dll_paths(target))

        for bdep in extra_bdeps:
            prospectives.add(bdep)
            if isinstance(bdep, build.BuildTarget):
                prospectives.update(bdep.get_transitive_link_deps())
        # Internal deps
        for ld in prospectives:
            dirseg = os.path.join(self.environment.get_build_dir(), self.get_target_dir(ld))
            result.add(dirseg)
        if (isinstance(target, build.BuildTarget) and
                not self.environment.machines.matches_build_machine(target.for_machine)):
            result.update(self.get_mingw_extra_paths(target))
        return list(result)

    def write_benchmark_file(self, datafile: T.BinaryIO) -> None:
        self.write_test_serialisation(self.build.get_benchmarks(), datafile)

    def write_test_file(self, datafile: T.BinaryIO) -> None:
        self.write_test_serialisation(self.build.get_tests(), datafile)

    def create_test_serialisation(self, tests: T.List['Test']) -> T.List[TestSerialisation]:
        arr: T.List[TestSerialisation] = []
        for t in sorted(tests, key=lambda tst: -1 * tst.priority):
            exe = t.get_exe()
            if isinstance(exe, programs.ExternalProgram):
                cmd = exe.get_command()
            else:
                cmd = [os.path.join(self.environment.get_build_dir(), self.get_target_filename(exe))]
            if isinstance(exe, (build.BuildTarget, programs.ExternalProgram)):
                test_for_machine = exe.for_machine
            else:
                # E.g. an external verifier or simulator program run on a generated executable.
                # Can always be run without a wrapper.
                test_for_machine = MachineChoice.BUILD

            # we allow passing compiled executables to tests, which may be cross built.
            # We need to consider these as well when considering whether the target is cross or not.
            for a in t.cmd_args:
                if isinstance(a, build.BuildTarget):
                    if a.for_machine is MachineChoice.HOST:
                        test_for_machine = MachineChoice.HOST
                        break

            is_cross = self.environment.is_cross_build(test_for_machine)
            exe_wrapper = self.environment.get_exe_wrapper()
            machine = self.environment.machines[exe.for_machine]
            if machine.is_windows() or machine.is_cygwin():
                extra_bdeps: T.List[T.Union[build.BuildTarget, build.CustomTarget]] = []
                if isinstance(exe, build.CustomTarget):
                    extra_bdeps = list(exe.get_transitive_build_target_deps())
                extra_paths = self.determine_windows_extra_paths(exe, extra_bdeps)
                for a in t.cmd_args:
                    if isinstance(a, build.BuildTarget):
                        for p in self.determine_windows_extra_paths(a, []):
                            if p not in extra_paths:
                                extra_paths.append(p)
            else:
                extra_paths = []

            cmd_args: T.List[str] = []
            depends: T.Set[build.Target] = set(t.depends)
            if isinstance(exe, build.Target):
                depends.add(exe)
            for a in t.cmd_args:
                if isinstance(a, build.Target):
                    depends.add(a)
                elif isinstance(a, build.CustomTargetIndex):
                    depends.add(a.target)

                if isinstance(a, mesonlib.File):
                    a = os.path.join(self.environment.get_build_dir(), a.rel_to_builddir(self.build_to_src))
                    cmd_args.append(a)
                elif isinstance(a, str):
                    cmd_args.append(a)
                elif isinstance(a, (build.Target, build.CustomTargetIndex)):
                    cmd_args.extend(self.construct_target_rel_paths(a, t.workdir))
                else:
                    raise MesonException('Bad object in test command.')

            t_env = copy.deepcopy(t.env)
            if not machine.is_windows() and not machine.is_cygwin() and not machine.is_darwin():
                ld_lib_path: T.Set[str] = set()
                for d in depends:
                    if isinstance(d, build.BuildTarget):
                        for l in d.get_all_link_deps():
                            if isinstance(l, build.SharedLibrary):
                                ld_lib_path.add(os.path.join(self.environment.get_build_dir(), l.get_output_subdir()))
                if ld_lib_path:
                    t_env.prepend('LD_LIBRARY_PATH', list(ld_lib_path), ':')

            ts = TestSerialisation(t.get_name(), t.project_name, t.suite, cmd, is_cross,
                                   exe_wrapper, self.environment.need_exe_wrapper(),
                                   t.is_parallel, cmd_args, t_env,
                                   t.should_fail, t.timeout, t.workdir,
                                   extra_paths, t.protocol, t.priority,
                                   isinstance(exe, (build.Target, build.CustomTargetIndex)),
                                   isinstance(exe, build.Executable),
                                   [x.get_id() for x in depends],
                                   self.environment.coredata.version,
                                   t.verbose)
            arr.append(ts)
        return arr

    def write_test_serialisation(self, tests: T.List['Test'], datafile: T.BinaryIO) -> None:
        pickle.dump(self.create_test_serialisation(tests), datafile)

    def construct_target_rel_paths(self, t: T.Union[build.Target, build.CustomTargetIndex], workdir: T.Optional[str]) -> T.List[str]:
        target_dir = self.get_target_dir(t)
        # ensure that test executables can be run when passed as arguments
        if isinstance(t, build.Executable) and workdir is None:
            target_dir = target_dir or '.'

        if isinstance(t, build.BuildTarget):
            outputs = [t.get_filename()]
        else:
            assert isinstance(t, (build.CustomTarget, build.CustomTargetIndex))
            outputs = t.get_outputs()

        outputs = [os.path.join(target_dir, x) for x in outputs]
        if workdir is not None:
            assert os.path.isabs(workdir)
            outputs = [os.path.join(self.environment.get_build_dir(), x) for x in outputs]
            outputs = [os.path.relpath(x, workdir) for x in outputs]
        return outputs

    def generate_depmf_install(self, d: InstallData) -> None:
        depmf_path = self.build.dep_manifest_name
        if depmf_path is None:
            option_dir = self.environment.coredata.get_option(OptionKey('licensedir'))
            assert isinstance(option_dir, str), 'for mypy'
            if option_dir:
                depmf_path = os.path.join(option_dir, 'depmf.json')
            else:
                return
        ifilename = os.path.join(self.environment.get_build_dir(), 'depmf.json')
        ofilename = os.path.join(self.environment.get_prefix(), depmf_path)
        odirname = os.path.join(self.environment.get_prefix(), os.path.dirname(depmf_path))
        out_name = os.path.join('{prefix}', depmf_path)
        out_dir = os.path.join('{prefix}', os.path.dirname(depmf_path))
        mfobj = {'type': 'dependency manifest', 'version': '1.0',
                 'projects': {k: v.to_json() for k, v in self.build.dep_manifest.items()}}
        with open(ifilename, 'w', encoding='utf-8') as f:
            f.write(json.dumps(mfobj))
        # Copy file from, to, and with mode unchanged
        d.data.append(InstallDataBase(ifilename, ofilename, out_name, None, '',
                                      tag='devel', data_type='depmf'))
        for m in self.build.dep_manifest.values():
            for ifilename, name in m.license_files:
                ofilename = os.path.join(odirname, name.relative_name())
                out_name = os.path.join(out_dir, name.relative_name())
                d.data.append(InstallDataBase(ifilename, ofilename, out_name, None,
                                              m.subproject, tag='devel', data_type='depmf'))

    def get_regen_filelist(self) -> T.List[str]:
        '''List of all files whose alteration means that the build
        definition needs to be regenerated.'''
        deps = OrderedSet([str(Path(self.build_to_src) / df)
                           for df in self.interpreter.get_build_def_files()])
        if self.environment.is_cross_build():
            deps.update(self.environment.coredata.cross_files)
        deps.update(self.environment.coredata.config_files)
        deps.add('meson-private/coredata.dat')
        self.check_clock_skew(deps)
        return list(deps)

    def generate_regen_info(self) -> None:
        deps = self.get_regen_filelist()
        regeninfo = RegenInfo(self.environment.get_source_dir(),
                              self.environment.get_build_dir(),
                              deps)
        filename = os.path.join(self.environment.get_scratch_dir(),
                                'regeninfo.dump')
        with open(filename, 'wb') as f:
            pickle.dump(regeninfo, f)

    def check_clock_skew(self, file_list: T.Iterable[str]) -> None:
        # If a file that leads to reconfiguration has a time
        # stamp in the future, it will trigger an eternal reconfigure
        # loop.
        import time
        now = time.time()
        for f in file_list:
            absf = os.path.join(self.environment.get_build_dir(), f)
            ftime = os.path.getmtime(absf)
            delta = ftime - now
            # On Windows disk time stamps sometimes point
            # to the future by a minuscule amount, less than
            # 0.001 seconds. I don't know why.
            if delta > 0.001:
                raise MesonException(f'Clock skew detected. File {absf} has a time stamp {delta:.4f}s in the future.')

    def build_target_to_cmd_array(self, bt: T.Union[build.BuildTarget, programs.ExternalProgram]) -> T.List[str]:
        if isinstance(bt, build.BuildTarget):
            arr = [os.path.join(self.environment.get_build_dir(), self.get_target_filename(bt))]
        else:
            arr = bt.get_command()
        return arr

    def replace_extra_args(self, args: T.List[str], genlist: 'build.GeneratedList') -> T.List[str]:
        final_args: T.List[str] = []
        for a in args:
            if a == '@EXTRA_ARGS@':
                final_args += genlist.get_extra_args()
            else:
                final_args.append(a)
        return final_args

    def replace_outputs(self, args: T.List[str], private_dir: str, output_list: T.List[str]) -> T.List[str]:
        newargs: T.List[str] = []
        regex = re.compile(r'@OUTPUT(\d+)@')
        for arg in args:
            m = regex.search(arg)
            while m is not None:
                index = int(m.group(1))
                src = f'@OUTPUT{index}@'
                arg = arg.replace(src, os.path.join(private_dir, output_list[index]))
                m = regex.search(arg)
            newargs.append(arg)
        return newargs

    def get_build_by_default_targets(self) -> 'T.OrderedDict[str, T.Union[build.BuildTarget, build.CustomTarget]]':
        result: 'T.OrderedDict[str, T.Union[build.BuildTarget, build.CustomTarget]]' = OrderedDict()
        # Get all build and custom targets that must be built by default
        for name, b in self.build.get_targets().items():
            if b.build_by_default:
                result[name] = b
        return result

    def get_testlike_targets(self, benchmark: bool = False) -> T.OrderedDict[str, T.Union[build.BuildTarget, build.CustomTarget]]:
        result: T.OrderedDict[str, T.Union[build.BuildTarget, build.CustomTarget]] = OrderedDict()
        targets = self.build.get_benchmarks() if benchmark else self.build.get_tests()
        for t in targets:
            exe = t.exe
            if isinstance(exe, (build.CustomTarget, build.BuildTarget)):
                result[exe.get_id()] = exe
            for arg in t.cmd_args:
                if not isinstance(arg, (build.CustomTarget, build.BuildTarget)):
                    continue
                result[arg.get_id()]
```
Response:
The user wants a summary of the functionality of the provided Python code. This code snippet is a part of the Meson build system, specifically the interpreter that handles the `meson.build` files.

Here's a breakdown of how to analyze the code and generate the requested information:

1. **Identify the Core Purpose:** The file is `interpreter.py`, so its primary role is to interpret and execute the instructions written in Meson's build definition language.

2. **Examine the Class:** The code defines a class, likely named `Interpreter` (or something similar, given the method names like `func_vcs_tag`, `func_custom_target`, etc.). This class is responsible for handling various Meson built-in functions.

3. **Analyze Individual Methods (Functions):** Each method starting with `func_` corresponds to a specific Meson function that users can call in their `meson.build` files. List these functions and their basic purpose by looking at the method name and docstring (if present, although less prevalent here). Keywords like `@typed_kwargs` and `@typed_pos_args` provide information about the arguments these functions accept.

4. **Look for Connections to Reverse Engineering:** Scan the function names and functionalities. Does anything directly relate to analyzing or modifying binaries? `vcs_tag` might be used to embed version information, which could be relevant in reverse engineering to identify versions. `custom_target` offers general build steps, some of which *could* be related to reverse engineering tools.

5. **Identify Low-Level Interactions:** Check for mentions of OS-specific features, kernels, or binary formats. The code interacts with files and processes, which are inherently tied to the underlying OS. Look for terms like "linux," "android," or mentions of binary formats (although less explicit here).

6. **Analyze Logic and Assumptions:**  For each function, consider what input it expects and what output it generates. `vcs_tag` likely takes input files and generates an output file containing version information. `custom_target` executes commands and produces output files.

7. **Consider User Errors:**  Think about how a user might misuse these functions. Incorrect arguments, missing dependencies, or invalid file paths are common errors. The `@typed_kwargs` and validation logic within the functions are designed to catch some of these.

8. **Trace User Interaction:**  How does a user get to this code? They write a `meson.build` file, and when Meson runs, it parses and interprets that file, leading to the execution of these interpreter methods.

9. **Synthesize the Information:** Combine the analysis of individual functions into a cohesive summary of the file's overall functionality.

**Self-Correction/Refinement during thought process:**

* **Initial thought:** Focus solely on the code provided.
* **Correction:** Recognize that this is *part* of a larger system (Meson) and the context of a build system is crucial for understanding the functionality.
* **Initial thought:**  Just list the functions.
* **Correction:**  Group functions by category (e.g., target creation, installation) for a more organized summary. Also, try to infer the broader purpose of each function (not just a literal description of what it does).
* **Initial thought:**  Focus only on explicit mentions of reverse engineering or low-level details.
* **Correction:**  Consider *potential* connections. While not directly a reverse engineering tool, Meson's build process can *include* steps relevant to reverse engineering. The ability to execute arbitrary commands via `custom_target` is a key aspect here.

By following these steps and considering the context of a build system interpreter, we can generate a comprehensive and accurate summary of the provided code.
这是 frida 动态Instrumentation 工具的源代码文件 `interpreter.py` 的一部分，它属于 Meson 构建系统的解释器模块。这个文件的主要功能是**解释和执行 `meson.build` 文件中定义的与构建目标相关的函数调用**。

以下是针对你提出的要求的详细功能列举和说明：

**1. 主要功能归纳：**

* **定义和处理构建目标:**  该文件包含多个以 `func_` 开头的函数，每个函数对应 `meson.build` 文件中定义的一种构建目标，例如：
    * `func_vcs_tag`: 处理版本控制系统的标签信息。
    * `func_custom_target`: 处理自定义构建目标，允许用户执行任意命令。
    * `func_run_target`: 定义一个需要运行的目标。
    * `func_alias_target`: 创建目标别名。
    * `func_generator`: 定义代码生成器。
    * `func_benchmark` 和 `func_test`: 定义基准测试和单元测试。
    * `func_install_headers`, `func_install_man`, `func_install_data`, `func_install_subdir`, `func_install_emptydir`, `func_install_symlink`: 处理各种安装操作。
    * `func_structured_sources`: 定义结构化源文件。
    * `func_subdir`: 处理进入子目录的操作。
    * `func_configure_file`: 处理配置文件生成。

* **参数解析和验证:**  每个 `func_` 函数都使用 `@typed_pos_args` 和 `@typed_kwargs` 装饰器来定义其接受的位置参数和关键字参数，并进行类型检查和验证，确保用户提供的参数符合预期。

* **构建对象的创建:**  这些函数会根据 `meson.build` 中的指令创建相应的构建对象 (如 `build.CustomTarget`, `build.Executable`, `build.InstallDir` 等)，并将这些对象添加到构建系统的内部数据结构中。

* **与底层构建系统的交互:**  这些函数会将高级的构建指令转换为底层构建系统（如 Ninja 或 Xcode）能够理解的指令。例如，`func_custom_target` 会生成执行特定命令的构建规则。

**2. 与逆向方法的关系及举例说明：**

* **`func_vcs_tag` (版本控制标签):**  在逆向工程中，了解软件的版本信息非常重要。`func_vcs_tag` 可以将代码仓库的版本信息嵌入到构建产物中（例如，写入到一个头文件中）。逆向工程师可以通过查看这个信息来快速确定目标软件的版本。

    * **举例:**  假设 `meson.build` 中有以下代码：
      ```meson
      vcs_tag(
          input: 'version.in',
          output: 'version.h',
          replace_string: '@VERSION@',
      )
      ```
      并且执行 `git describe --tags` 输出 `v1.2.3-4-gabcdef`。那么，生成的 `version.h` 文件可能会包含类似 `#define VERSION "v1.2.3-4-gabcdef"` 的内容。逆向工程师通过查看这个头文件就可以知道软件的版本信息。

* **`func_custom_target` (自定义构建目标):**  该功能非常灵活，可以执行任何用户指定的命令。这在逆向工程中有很多应用场景：
    * **执行反汇编器或反编译器:**  可以使用 `custom_target` 在构建过程中自动运行反汇编器 (如 `objdump`, `ida`) 或反编译器 (如 `ghidra`)，并将输出保存到文件中供后续分析。
    * **执行静态分析工具:**  可以使用 `custom_target` 运行静态分析工具 (如 `valgrind`, `clang-tidy`) 来检查代码中的潜在问题，这有助于理解代码行为。
    * **打包和解包二进制文件:**  可以使用 `custom_target` 来打包或解包特定的二进制格式，以便进行深入分析。

    * **假设输入:**  `meson.build` 中定义了一个自定义目标来反汇编一个可执行文件：
      ```meson
      executable('my_program', 'my_program.c')

      custom_target(
          'disassemble',
          command: ['objdump', '-d', '@INPUT@', '>', '@OUTPUT@'],
          input: 'my_program',
          output: 'my_program.asm',
      )
      ```
    * **预期输出:**  执行构建后，会生成一个名为 `my_program.asm` 的文件，其中包含了 `my_program` 可执行文件的反汇编代码。

**3. 涉及二进制底层、Linux、Android内核及框架的知识及举例说明：**

* **二进制底层:**
    * `func_custom_target` 可以用来操作二进制文件，例如修改二进制文件的某些字节，这需要对二进制文件的格式有深入的理解。
    * 构建过程中生成的可执行文件、库文件等都是二进制格式，Meson 负责协调它们的编译和链接。

* **Linux:**
    * **文件权限和模式 (`INSTALL_MODE_KW`):**  `func_install_headers`, `func_install_man`, `func_install_data`, `func_install_subdir` 等函数涉及到文件安装，它们可以使用 `INSTALL_MODE_KW` 来设置安装文件的权限，这直接关联到 Linux 的文件权限模型。
    * **环境变量 (`ENV_KW`):**  `func_custom_target`, `func_run_target`, `func_test` 等函数允许设置执行命令时的环境变量，这与 Linux 的进程环境密切相关。
    * **Man 手册 (`func_install_man`):**  该函数用于安装 man 手册，这是 Linux 系统中常用的文档格式。

* **Android内核及框架:**
    * 虽然代码本身没有直接提及 Android 内核或框架，但 Frida 作为一款动态 Instrumentation 工具，主要应用于 Android 和 Linux 等平台。Meson 作为 Frida 的构建系统，其生成的构建产物最终会运行在这些平台上。
    * **交叉编译:**  构建 Frida 时可能需要进行交叉编译，以便在目标 Android 设备上运行。Meson 能够处理这种复杂的构建场景。
    * **动态链接库 (`.so` 文件):**  Frida 的核心功能通常以动态链接库的形式提供，Meson 负责这些库的编译和链接。

**4. 逻辑推理及假设输入与输出：**

* **`func_subdir` (处理子目录):**  该函数用于处理进入子目录并执行其 `meson.build` 文件的逻辑。
    * **假设输入:** 当前 `meson.build` 文件位于 `/path/to/project/`，并且调用了 `subdir('src')`。
    * **逻辑推理:**
        1. 解释器会检查 `/path/to/project/src/` 目录下是否存在 `meson.build` 文件。
        2. 如果存在，则读取并解析该文件。
        3. 递归调用解释器来执行子目录的 `meson.build` 文件。
        4. 执行完毕后，返回到父目录的上下文中。
    * **预期输出:**  子目录中定义的构建目标会被添加到整个项目的构建图中。

* **`func_install_data` (安装数据文件):**
    * **假设输入:** `meson.build` 文件中有以下代码：
      ```meson
      install_data('config.ini', install_dir: '/etc/my_app')
      ```
      并且 `config.ini` 文件存在于当前源目录下。
    * **逻辑推理:**
        1. 解释器会识别出需要安装 `config.ini` 文件。
        2. 它会确定安装目标路径为 `/etc/my_app`。
        3. 构建系统会生成相应的安装规则，将 `config.ini` 文件复制到构建目录下的对应位置。
    * **预期输出:**  在执行 `meson install` 命令后，`config.ini` 文件会被复制到系统的 `/etc/my_app` 目录下。

**5. 涉及用户或编程常见的使用错误及举例说明：**

* **`func_custom_target` (自定义构建目标):**
    * **错误:**  忘记设置 `output` 参数，或者 `output` 参数与命令的实际输出不符。
    * **举例:**
      ```meson
      custom_target('my_gen_file',
          command: ['my_generator.sh', '@INPUT@', 'generated.txt'],
          input: 'input.txt',
          # 缺少 output 参数
      )
      ```
      这将导致构建系统无法正确跟踪生成的文件，可能导致增量构建失败。

* **`func_install_headers` (安装头文件):**
    * **错误:**  `install_dir` 和 `subdir` 参数同时使用。
    * **举例:**
      ```meson
      install_headers('my_header.h', install_dir: '/usr/include/my_app', subdir: 'include')
      ```
      这将导致 Meson 报错，因为只能指定一个安装目录。

* **`func_subdir` (处理子目录):**
    * **错误:**  尝试进入不存在的子目录。
    * **举例:**
      ```meson
      subdir('non_existent_dir')
      ```
      这将导致 Meson 报错，提示找不到构建文件。

**6. 用户操作如何一步步到达这里，作为调试线索：**

1. **用户编写 `meson.build` 文件:**  用户首先根据项目需求，编写包含各种构建指令的 `meson.build` 文件。这些指令会调用该文件中定义的 `func_` 函数。

2. **用户运行 `meson` 命令:**  用户在项目根目录下运行 `meson <build_directory>` 命令来配置构建系统。

3. **Meson 解析 `meson.build` 文件:**  `meson` 命令会读取并解析项目根目录以及所有子目录下的 `meson.build` 文件。

4. **调用解释器模块:**  在解析过程中，当遇到与构建目标相关的函数调用时 (例如 `custom_target`, `executable`, `install_data` 等)，Meson 会调用 `interpreter.py` 文件中的相应 `func_` 函数。

5. **执行 `func_` 函数:**  `interpreter.py` 中的函数会根据 `meson.build` 文件中提供的参数进行解析、验证，并创建相应的构建对象。

6. **构建图生成:**  这些构建对象会被添加到 Meson 的内部构建图中，描述了项目的所有构建任务和依赖关系。

7. **代码生成 (例如 Ninja 文件):**  最终，Meson 会根据构建图生成底层构建系统 (如 Ninja) 所需的构建文件。

**作为调试线索:**  当用户在配置构建时遇到错误，例如 Meson 报错提示参数类型错误或缺少参数，那么调试线索就会指向 `interpreter.py` 文件中相应的 `func_` 函数，因为这些函数负责参数的解析和验证。查看这些函数的定义和参数验证逻辑可以帮助理解错误的原因。

**总结 `interpreter.py` 的功能 (第 4 部分)：**

到目前为止，我们分析了 `interpreter.py` 文件中关于定义和处理各种构建目标的函数 (如 `vcs_tag`, `custom_target`, `run_target`, `alias_target`, `generator`, `benchmark`, `test`, `install_headers`, `install_man`, `install_emptydir`, `install_symlink`, `structured_sources`, `subdir`, `install_data`, `install_subdir`)。这些函数负责解释 `meson.build` 文件中的指令，进行参数解析和验证，并创建相应的构建对象，最终构建出项目的软件产物。它们是 Meson 构建系统的核心组成部分，将用户友好的构建描述转换为底层构建系统可以执行的指令。

### 提示词
```
这是目录为frida/subprojects/frida-node/releng/meson/mesonbuild/interpreter/interpreter.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共6部分，请归纳一下它的功能
```

### 源代码
```python
=True),
        MULTI_OUTPUT_KW,
        # Cannot use the COMMAND_KW because command is allowed to be empty
        KwargInfo(
            'command',
            ContainerTypeInfo(list, (str, build.BuildTarget, build.CustomTarget, build.CustomTargetIndex, ExternalProgram, mesonlib.File)),
            listify=True,
            default=[],
        ),
        KwargInfo('fallback', (str, NoneType)),
        KwargInfo('replace_string', str, default='@VCS_TAG@'),
    )
    def func_vcs_tag(self, node: mparser.BaseNode, args: T.List['TYPE_var'], kwargs: 'kwtypes.VcsTag') -> build.CustomTarget:
        if kwargs['fallback'] is None:
            FeatureNew.single_use('Optional fallback in vcs_tag', '0.41.0', self.subproject, location=node)
        fallback = kwargs['fallback'] or self.project_version
        replace_string = kwargs['replace_string']
        regex_selector = '(.*)' # default regex selector for custom command: use complete output
        vcs_cmd = kwargs['command']
        source_dir = os.path.normpath(os.path.join(self.environment.get_source_dir(), self.subdir))
        if vcs_cmd:
            if isinstance(vcs_cmd[0], (str, mesonlib.File)):
                if isinstance(vcs_cmd[0], mesonlib.File):
                    FeatureNew.single_use('vcs_tag with file as the first argument', '0.62.0', self.subproject, location=node)
                maincmd = self.find_program_impl(vcs_cmd[0], required=False)
                if maincmd.found():
                    vcs_cmd[0] = maincmd
            else:
                FeatureNew.single_use('vcs_tag with custom_tgt, external_program, or exe as the first argument', '0.63.0', self.subproject, location=node)
        else:
            vcs = mesonlib.detect_vcs(source_dir)
            if vcs:
                mlog.log('Found {} repository at {}'.format(vcs['name'], vcs['wc_dir']))
                vcs_cmd = vcs['get_rev'].split()
                regex_selector = vcs['rev_regex']
            else:
                vcs_cmd = [' '] # executing this cmd will fail in vcstagger.py and force to use the fallback string
        # vcstagger.py parameters: infile, outfile, fallback, source_dir, replace_string, regex_selector, command...

        self._validate_custom_target_outputs(len(kwargs['input']) > 1, kwargs['output'], "vcs_tag")

        cmd = self.environment.get_build_command() + \
            ['--internal',
             'vcstagger',
             '@INPUT0@',
             '@OUTPUT0@',
             fallback,
             source_dir,
             replace_string,
             regex_selector] + vcs_cmd

        tg = build.CustomTarget(
            kwargs['output'][0],
            self.subdir,
            self.subproject,
            self.environment,
            cmd,
            self.source_strings_to_files(kwargs['input']),
            kwargs['output'],
            self.coredata.is_build_only,
            build_by_default=True,
            build_always_stale=True,
        )
        self.add_target(tg.name, tg)
        return tg

    @FeatureNew('subdir_done', '0.46.0')
    @noPosargs
    @noKwargs
    def func_subdir_done(self, node: mparser.BaseNode, args: TYPE_var, kwargs: TYPE_kwargs) -> T.NoReturn:
        raise SubdirDoneRequest()

    @staticmethod
    def _validate_custom_target_outputs(has_multi_in: bool, outputs: T.Iterable[str], name: str) -> None:
        """Checks for additional invalid values in a custom_target output.

        This cannot be done with typed_kwargs because it requires the number of
        inputs.
        """
        for out in outputs:
            if has_multi_in and ('@PLAINNAME@' in out or '@BASENAME@' in out):
                raise InvalidArguments(f'{name}: output cannot contain "@PLAINNAME@" or "@BASENAME@" '
                                       'when there is more than one input (we can\'t know which to use)')

    @typed_pos_args('custom_target', optargs=[str])
    @typed_kwargs(
        'custom_target',
        COMMAND_KW,
        CT_BUILD_ALWAYS,
        CT_BUILD_ALWAYS_STALE,
        CT_BUILD_BY_DEFAULT,
        CT_INPUT_KW,
        CT_INSTALL_DIR_KW,
        CT_INSTALL_TAG_KW,
        MULTI_OUTPUT_KW,
        DEPENDS_KW,
        DEPEND_FILES_KW,
        DEPFILE_KW,
        ENV_KW.evolve(since='0.57.0'),
        INSTALL_KW,
        INSTALL_MODE_KW.evolve(since='0.47.0'),
        KwargInfo('feed', bool, default=False, since='0.59.0'),
        KwargInfo('capture', bool, default=False),
        KwargInfo('console', bool, default=False, since='0.48.0'),
    )
    def func_custom_target(self, node: mparser.FunctionNode, args: T.Tuple[str],
                           kwargs: 'kwtypes.CustomTarget') -> build.CustomTarget:
        if kwargs['depfile'] and ('@BASENAME@' in kwargs['depfile'] or '@PLAINNAME@' in kwargs['depfile']):
            FeatureNew.single_use('substitutions in custom_target depfile', '0.47.0', self.subproject, location=node)
        install_mode = self._warn_kwarg_install_mode_sticky(kwargs['install_mode'])

        # Don't mutate the kwargs

        build_by_default = kwargs['build_by_default']
        build_always_stale = kwargs['build_always_stale']
        # Remap build_always to build_by_default and build_always_stale
        if kwargs['build_always'] is not None and kwargs['build_always_stale'] is not None:
            raise InterpreterException('CustomTarget: "build_always" and "build_always_stale" are mutually exclusive')

        if build_by_default is None and kwargs['install']:
            build_by_default = True

        elif kwargs['build_always'] is not None:
            if build_by_default is None:
                build_by_default = kwargs['build_always']
            build_always_stale = kwargs['build_by_default']

        # These are nullable so that we can know whether they're explicitly
        # set or not. If they haven't been overwritten, set them to their true
        # default
        if build_by_default is None:
            build_by_default = False
        if build_always_stale is None:
            build_always_stale = False

        name = args[0]
        if name is None:
            # name will default to first output, but we cannot do that yet because
            # they could need substitutions (e.g. @BASENAME@) first. CustomTarget()
            # will take care of setting a proper default but name must be an empty
            # string in the meantime.
            FeatureNew.single_use('custom_target() with no name argument', '0.60.0', self.subproject, location=node)
            name = ''
        inputs = self.source_strings_to_files(kwargs['input'], strict=False)
        command = kwargs['command']
        if command and isinstance(command[0], str):
            command[0] = self.find_program_impl([command[0]])

        if len(inputs) > 1 and kwargs['feed']:
            raise InvalidArguments('custom_target: "feed" keyword argument can only be used with a single input')
        if len(kwargs['output']) > 1 and kwargs['capture']:
            raise InvalidArguments('custom_target: "capture" keyword argument can only be used with a single output')
        if kwargs['capture'] and kwargs['console']:
            raise InvalidArguments('custom_target: "capture" and "console" keyword arguments are mutually exclusive')
        for c in command:
            if kwargs['capture'] and isinstance(c, str) and '@OUTPUT@' in c:
                raise InvalidArguments('custom_target: "capture" keyword argument cannot be used with "@OUTPUT@"')
            if kwargs['feed'] and isinstance(c, str) and '@INPUT@' in c:
                raise InvalidArguments('custom_target: "feed" keyword argument cannot be used with "@INPUT@"')
        if kwargs['install'] and not kwargs['install_dir']:
            raise InvalidArguments('custom_target: "install_dir" keyword argument must be set when "install" is true.')
        if len(kwargs['install_dir']) > 1:
            FeatureNew.single_use('multiple install_dir for custom_target', '0.40.0', self.subproject, location=node)
        if len(kwargs['install_tag']) not in {0, 1, len(kwargs['output'])}:
            raise InvalidArguments('custom_target: install_tag argument must have 0 or 1 outputs, '
                                   'or the same number of elements as the output keyword argument. '
                                   f'(there are {len(kwargs["install_tag"])} install_tags, '
                                   f'and {len(kwargs["output"])} outputs)')

        for t in kwargs['output']:
            self.validate_forbidden_targets(t)
        self._validate_custom_target_outputs(len(inputs) > 1, kwargs['output'], "custom_target")

        tg = build.CustomTarget(
            name,
            self.subdir,
            self.subproject,
            self.environment,
            command,
            inputs,
            kwargs['output'],
            self.coredata.is_build_only,
            build_always_stale=build_always_stale,
            build_by_default=build_by_default,
            capture=kwargs['capture'],
            console=kwargs['console'],
            depend_files=kwargs['depend_files'],
            depfile=kwargs['depfile'],
            extra_depends=kwargs['depends'],
            env=kwargs['env'],
            feed=kwargs['feed'],
            install=kwargs['install'],
            install_dir=kwargs['install_dir'],
            install_mode=install_mode,
            install_tag=kwargs['install_tag'],
            backend=self.backend)
        self.add_target(tg.name, tg)
        return tg

    @typed_pos_args('run_target', str)
    @typed_kwargs(
        'run_target',
        COMMAND_KW,
        DEPENDS_KW,
        ENV_KW.evolve(since='0.57.0'),
    )
    def func_run_target(self, node: mparser.FunctionNode, args: T.Tuple[str],
                        kwargs: 'kwtypes.RunTarget') -> build.RunTarget:
        all_args = kwargs['command'].copy()

        for i in listify(all_args):
            if isinstance(i, ExternalProgram) and not i.found():
                raise InterpreterException(f'Tried to use non-existing executable {i.name!r}')
        if isinstance(all_args[0], str):
            all_args[0] = self.find_program_impl([all_args[0]])
        name = args[0]
        tg = build.RunTarget(name, all_args, kwargs['depends'], self.subdir, self.subproject, self.environment,
                             kwargs['env'])
        self.add_target(name, tg)
        return tg

    @FeatureNew('alias_target', '0.52.0')
    @typed_pos_args('alias_target', str, varargs=build.Target, min_varargs=1)
    @noKwargs
    def func_alias_target(self, node: mparser.BaseNode, args: T.Tuple[str, T.List[build.Target]],
                          kwargs: 'TYPE_kwargs') -> build.AliasTarget:
        name, deps = args
        if any(isinstance(d, build.RunTarget) for d in deps):
            FeatureNew.single_use('alias_target that depends on run_targets', '0.60.0', self.subproject)
        tg = build.AliasTarget(name, deps, self.subdir, self.subproject, self.environment)
        self.add_target(name, tg)
        return tg

    @typed_pos_args('generator', (build.Executable, ExternalProgram))
    @typed_kwargs(
        'generator',
        KwargInfo('arguments', ContainerTypeInfo(list, str, allow_empty=False), required=True, listify=True),
        KwargInfo('output', ContainerTypeInfo(list, str, allow_empty=False), required=True, listify=True),
        DEPFILE_KW,
        DEPENDS_KW,
        KwargInfo('capture', bool, default=False, since='0.43.0'),
    )
    def func_generator(self, node: mparser.FunctionNode,
                       args: T.Tuple[T.Union[build.Executable, ExternalProgram]],
                       kwargs: 'kwtypes.FuncGenerator') -> build.Generator:
        for rule in kwargs['output']:
            if '@BASENAME@' not in rule and '@PLAINNAME@' not in rule:
                raise InvalidArguments('Every element of "output" must contain @BASENAME@ or @PLAINNAME@.')
            if has_path_sep(rule):
                raise InvalidArguments('"output" must not contain a directory separator.')
        if len(kwargs['output']) > 1:
            for o in kwargs['output']:
                if '@OUTPUT@' in o:
                    raise InvalidArguments('Tried to use @OUTPUT@ in a rule with more than one output.')

        gen = build.Generator(args[0], **kwargs)
        self.generators.append(gen)
        return gen

    @typed_pos_args('benchmark', str, (build.Executable, build.Jar, ExternalProgram, mesonlib.File, build.CustomTarget, build.CustomTargetIndex))
    @typed_kwargs('benchmark', *TEST_KWS)
    def func_benchmark(self, node: mparser.BaseNode,
                       args: T.Tuple[str, T.Union[build.Executable, build.Jar, ExternalProgram, mesonlib.File]],
                       kwargs: 'kwtypes.FuncBenchmark') -> None:
        self.add_test(node, args, kwargs, False)

    @typed_pos_args('test', str, (build.Executable, build.Jar, ExternalProgram, mesonlib.File, build.CustomTarget, build.CustomTargetIndex))
    @typed_kwargs('test', *TEST_KWS, KwargInfo('is_parallel', bool, default=True))
    def func_test(self, node: mparser.BaseNode,
                  args: T.Tuple[str, T.Union[build.Executable, build.Jar, ExternalProgram, mesonlib.File, build.CustomTarget, build.CustomTargetIndex]],
                  kwargs: 'kwtypes.FuncTest') -> None:
        self.add_test(node, args, kwargs, True)

    def unpack_env_kwarg(self, kwargs: T.Union[EnvironmentVariables, T.Dict[str, 'TYPE_var'], T.List['TYPE_var'], str]) -> EnvironmentVariables:
        envlist = kwargs.get('env')
        if envlist is None:
            return EnvironmentVariables()
        msg = ENV_KW.validator(envlist)
        if msg:
            raise InvalidArguments(f'"env": {msg}')
        return ENV_KW.convertor(envlist)

    def make_test(self, node: mparser.BaseNode,
                  args: T.Tuple[str, T.Union[build.Executable, build.Jar, ExternalProgram, mesonlib.File, build.CustomTarget, build.CustomTargetIndex]],
                  kwargs: 'kwtypes.BaseTest') -> Test:
        name = args[0]
        if ':' in name:
            mlog.deprecation(f'":" is not allowed in test name "{name}", it has been replaced with "_"',
                             location=node)
            name = name.replace(':', '_')
        exe = args[1]
        if isinstance(exe, ExternalProgram):
            if not exe.found():
                raise InvalidArguments('Tried to use not-found external program as test exe')
        elif isinstance(exe, mesonlib.File):
            exe = self.find_program_impl([exe])
        elif isinstance(exe, build.CustomTarget):
            kwargs.setdefault('depends', []).append(exe)
        elif isinstance(exe, build.CustomTargetIndex):
            kwargs.setdefault('depends', []).append(exe.target)

        env = self.unpack_env_kwarg(kwargs)

        if kwargs['timeout'] <= 0:
            FeatureNew.single_use('test() timeout <= 0', '0.57.0', self.subproject, location=node)

        prj = self.subproject if self.is_subproject() else self.build.project_name

        suite: T.List[str] = []
        for s in kwargs['suite']:
            if s:
                s = ':' + s
            suite.append(prj.replace(' ', '_').replace(':', '_') + s)

        return Test(name,
                    prj,
                    suite,
                    exe,
                    kwargs['depends'],
                    kwargs.get('is_parallel', False),
                    kwargs['args'],
                    env,
                    kwargs['should_fail'],
                    kwargs['timeout'],
                    kwargs['workdir'],
                    kwargs['protocol'],
                    kwargs['priority'],
                    kwargs['verbose'])

    def add_test(self, node: mparser.BaseNode,
                 args: T.Tuple[str, T.Union[build.Executable, build.Jar, ExternalProgram, mesonlib.File, build.CustomTarget, build.CustomTargetIndex]],
                 kwargs: T.Dict[str, T.Any], is_base_test: bool):
        if isinstance(args[1], (build.CustomTarget, build.CustomTargetIndex)):
            FeatureNew.single_use('test with CustomTarget as command', '1.4.0', self.subproject)

        t = self.make_test(node, args, kwargs)
        if is_base_test:
            self.build.tests.append(t)
            mlog.debug('Adding test', mlog.bold(t.name, True))
        else:
            self.build.benchmarks.append(t)
            mlog.debug('Adding benchmark', mlog.bold(t.name, True))

    @typed_pos_args('install_headers', varargs=(str, mesonlib.File))
    @typed_kwargs(
        'install_headers',
        PRESERVE_PATH_KW,
        KwargInfo('subdir', (str, NoneType)),
        INSTALL_MODE_KW.evolve(since='0.47.0'),
        INSTALL_DIR_KW,
        INSTALL_FOLLOW_SYMLINKS,
    )
    def func_install_headers(self, node: mparser.BaseNode,
                             args: T.Tuple[T.List['mesonlib.FileOrString']],
                             kwargs: 'kwtypes.FuncInstallHeaders') -> build.Headers:
        install_mode = self._warn_kwarg_install_mode_sticky(kwargs['install_mode'])
        source_files = self.source_strings_to_files(args[0])
        install_subdir = kwargs['subdir']
        if install_subdir is not None:
            if kwargs['install_dir'] is not None:
                raise InterpreterException('install_headers: cannot specify both "install_dir" and "subdir". Use only "install_dir".')
            if os.path.isabs(install_subdir):
                mlog.deprecation('Subdir keyword must not be an absolute path. This will be a hard error in the next release.')
        else:
            install_subdir = ''

        dirs = collections.defaultdict(list)
        ret_headers = []
        if kwargs['preserve_path']:
            for file in source_files:
                dirname = os.path.dirname(file.fname)
                dirs[dirname].append(file)
        else:
            dirs[''].extend(source_files)

        for childdir in dirs:
            h = build.Headers(dirs[childdir], os.path.join(install_subdir, childdir), kwargs['install_dir'],
                              install_mode, self.subproject,
                              follow_symlinks=kwargs['follow_symlinks'])
            ret_headers.append(h)
            self.build.headers.append(h)

        return ret_headers

    @typed_pos_args('install_man', varargs=(str, mesonlib.File))
    @typed_kwargs(
        'install_man',
        KwargInfo('locale', (str, NoneType), since='0.58.0'),
        INSTALL_MODE_KW.evolve(since='0.47.0'),
        INSTALL_DIR_KW,
    )
    def func_install_man(self, node: mparser.BaseNode,
                         args: T.Tuple[T.List['mesonlib.FileOrString']],
                         kwargs: 'kwtypes.FuncInstallMan') -> build.Man:
        install_mode = self._warn_kwarg_install_mode_sticky(kwargs['install_mode'])
        # We just need to narrow this, because the input is limited to files and
        # Strings as inputs, so only Files will be returned
        sources = self.source_strings_to_files(args[0])
        for s in sources:
            try:
                num = int(s.rsplit('.', 1)[-1])
            except (IndexError, ValueError):
                num = 0
            if not 1 <= num <= 9:
                raise InvalidArguments('Man file must have a file extension of a number between 1 and 9')

        m = build.Man(sources, kwargs['install_dir'], install_mode,
                      self.subproject, kwargs['locale'])
        self.build.man.append(m)

        return m

    @FeatureNew('install_emptydir', '0.60.0')
    @typed_kwargs(
        'install_emptydir',
        INSTALL_MODE_KW,
        KwargInfo('install_tag', (str, NoneType), since='0.62.0')
    )
    def func_install_emptydir(self, node: mparser.BaseNode, args: T.Tuple[str], kwargs) -> None:
        d = build.EmptyDir(args[0], kwargs['install_mode'], self.subproject, kwargs['install_tag'])
        self.build.emptydir.append(d)

        return d

    @FeatureNew('install_symlink', '0.61.0')
    @typed_pos_args('symlink_name', str)
    @typed_kwargs(
        'install_symlink',
        KwargInfo('pointing_to', str, required=True),
        KwargInfo('install_dir', str, required=True),
        INSTALL_TAG_KW,
    )
    def func_install_symlink(self, node: mparser.BaseNode,
                             args: T.Tuple[T.List[str]],
                             kwargs) -> build.SymlinkData:
        name = args[0] # Validation while creating the SymlinkData object
        target = kwargs['pointing_to']
        l = build.SymlinkData(target, name, kwargs['install_dir'],
                              self.subproject, kwargs['install_tag'])
        self.build.symlinks.append(l)
        return l

    @FeatureNew('structured_sources', '0.62.0')
    @typed_pos_args('structured_sources', object, optargs=[dict])
    @noKwargs
    @noArgsFlattening
    def func_structured_sources(
            self, node: mparser.BaseNode,
            args: T.Tuple[object, T.Optional[T.Dict[str, object]]],
            kwargs: 'TYPE_kwargs') -> build.StructuredSources:
        valid_types = (str, mesonlib.File, build.GeneratedList, build.CustomTarget, build.CustomTargetIndex, build.GeneratedList)
        sources: T.Dict[str, T.List[T.Union[mesonlib.File, 'build.GeneratedTypes']]] = collections.defaultdict(list)

        for arg in mesonlib.listify(args[0]):
            if not isinstance(arg, valid_types):
                raise InvalidArguments(f'structured_sources: type "{type(arg)}" is not valid')
            if isinstance(arg, str):
                arg = mesonlib.File.from_source_file(self.environment.source_dir, self.subdir, arg)
            sources[''].append(arg)
        if args[1]:
            if '' in args[1]:
                raise InvalidArguments('structured_sources: keys to dictionary argument may not be an empty string.')
            for k, v in args[1].items():
                for arg in mesonlib.listify(v):
                    if not isinstance(arg, valid_types):
                        raise InvalidArguments(f'structured_sources: type "{type(arg)}" is not valid')
                    if isinstance(arg, str):
                        arg = mesonlib.File.from_source_file(self.environment.source_dir, self.subdir, arg)
                    sources[k].append(arg)
        return build.StructuredSources(sources)

    @typed_pos_args('subdir', str)
    @typed_kwargs(
        'subdir',
        KwargInfo(
            'if_found',
            ContainerTypeInfo(list, object),
            validator=lambda a: 'Objects must have a found() method' if not all(hasattr(x, 'found') for x in a) else None,
            since='0.44.0',
            default=[],
            listify=True,
        ),
    )
    def func_subdir(self, node: mparser.BaseNode, args: T.Tuple[str], kwargs: 'kwtypes.Subdir') -> None:
        mesonlib.check_direntry_issues(args)
        if '..' in args[0]:
            raise InvalidArguments('Subdir contains ..')
        if self.subdir == '' and args[0] == self.subproject_dir:
            raise InvalidArguments('Must not go into subprojects dir with subdir(), use subproject() instead.')
        if self.subdir == '' and args[0].startswith('meson-'):
            raise InvalidArguments('The "meson-" prefix is reserved and cannot be used for top-level subdir().')
        if args[0] == '':
            raise InvalidArguments("The argument given to subdir() is the empty string ''. This is prohibited.")
        for i in kwargs['if_found']:
            if not i.found():
                return

        prev_subdir = self.subdir
        subdir = os.path.join(prev_subdir, args[0])
        if os.path.isabs(subdir):
            raise InvalidArguments('Subdir argument must be a relative path.')
        absdir = os.path.join(self.environment.get_source_dir(), subdir)
        symlinkless_dir = os.path.realpath(absdir)
        build_file = os.path.join(symlinkless_dir, 'meson.build')
        if build_file in self.processed_buildfiles:
            raise InvalidArguments(f'Tried to enter directory "{subdir}", which has already been visited.')
        self.processed_buildfiles.add(build_file)
        self.subdir = subdir
        os.makedirs(self.absolute_builddir_path_for(subdir), exist_ok=True)
        buildfilename = os.path.join(self.subdir, environment.build_filename)
        self.build_def_files.add(buildfilename)
        absname = os.path.join(self.environment.get_source_dir(), buildfilename)
        if not os.path.isfile(absname):
            self.subdir = prev_subdir
            raise InterpreterException(f"Nonexistent build file '{buildfilename!s}'")
        with open(absname, encoding='utf-8') as f:
            code = f.read()
        assert isinstance(code, str)
        try:
            codeblock = mparser.Parser(code, absname).parse()
        except mesonlib.MesonException as me:
            me.file = absname
            raise me
        try:
            self.evaluate_codeblock(codeblock)
        except SubdirDoneRequest:
            pass
        self.subdir = prev_subdir

    # This is either ignored on basically any OS nowadays, or silently gets
    # ignored (Solaris) or triggers an "illegal operation" error (FreeBSD).
    # It was likely added "because it exists", but should never be used. In
    # theory it is useful for directories, but we never apply modes to
    # directories other than in install_emptydir.
    def _warn_kwarg_install_mode_sticky(self, mode: FileMode) -> None:
        if mode.perms > 0 and mode.perms & stat.S_ISVTX:
            mlog.deprecation('install_mode with the sticky bit on a file does not do anything and will '
                             'be ignored since Meson 0.64.0', location=self.current_node)
            perms = stat.filemode(mode.perms - stat.S_ISVTX)[1:]
            return FileMode(perms, mode.owner, mode.group)
        else:
            return mode

    @typed_pos_args('install_data', varargs=(str, mesonlib.File))
    @typed_kwargs(
        'install_data',
        KwargInfo('sources', ContainerTypeInfo(list, (str, mesonlib.File)), listify=True, default=[]),
        KwargInfo('rename', ContainerTypeInfo(list, str), default=[], listify=True, since='0.46.0'),
        INSTALL_MODE_KW.evolve(since='0.38.0'),
        INSTALL_TAG_KW.evolve(since='0.60.0'),
        INSTALL_DIR_KW,
        PRESERVE_PATH_KW.evolve(since='0.64.0'),
        INSTALL_FOLLOW_SYMLINKS,
    )
    def func_install_data(self, node: mparser.BaseNode,
                          args: T.Tuple[T.List['mesonlib.FileOrString']],
                          kwargs: 'kwtypes.FuncInstallData') -> build.Data:
        sources = self.source_strings_to_files(args[0] + kwargs['sources'])
        rename = kwargs['rename'] or None
        if rename:
            if len(rename) != len(sources):
                raise InvalidArguments(
                    '"rename" and "sources" argument lists must be the same length if "rename" is given. '
                    f'Rename has {len(rename)} elements and sources has {len(sources)}.')

        install_dir = kwargs['install_dir']
        if not install_dir:
            subdir = self.active_projectname
            install_dir = P_OBJ.OptionString(os.path.join(self.environment.get_datadir(), subdir), os.path.join('{datadir}', subdir))
            if self.is_subproject():
                FeatureNew.single_use('install_data() without install_dir inside of a subproject', '1.3.0', self.subproject,
                                      'This was broken and would install to the project name of the parent project instead',
                                      node)
            if kwargs['preserve_path']:
                FeatureNew.single_use('install_data() with preserve_path and without install_dir', '1.3.0', self.subproject,
                                      'This was broken and would not add the project name to the install path',
                                      node)

        install_mode = self._warn_kwarg_install_mode_sticky(kwargs['install_mode'])
        return self.install_data_impl(sources, install_dir, install_mode, rename, kwargs['install_tag'],
                                      preserve_path=kwargs['preserve_path'],
                                      follow_symlinks=kwargs['follow_symlinks'])

    def install_data_impl(self, sources: T.List[mesonlib.File], install_dir: str,
                          install_mode: FileMode, rename: T.Optional[str],
                          tag: T.Optional[str],
                          install_data_type: T.Optional[str] = None,
                          preserve_path: bool = False,
                          follow_symlinks: T.Optional[bool] = None) -> build.Data:
        install_dir_name = install_dir.optname if isinstance(install_dir, P_OBJ.OptionString) else install_dir
        dirs = collections.defaultdict(list)
        if preserve_path:
            for file in sources:
                dirname = os.path.dirname(file.fname)
                dirs[dirname].append(file)
        else:
            dirs[''].extend(sources)

        ret_data = []
        for childdir, files in dirs.items():
            d = build.Data(files, os.path.join(install_dir, childdir), os.path.join(install_dir_name, childdir),
                           install_mode, self.subproject, rename, tag, install_data_type,
                           follow_symlinks)
            ret_data.append(d)

        self.build.data.extend(ret_data)
        return ret_data

    @typed_pos_args('install_subdir', str)
    @typed_kwargs(
        'install_subdir',
        KwargInfo('install_dir', str, required=True),
        KwargInfo('strip_directory', bool, default=False),
        KwargInfo('exclude_files', ContainerTypeInfo(list, str),
                  default=[], listify=True, since='0.42.0',
                  validator=lambda x: 'cannot be absolute' if any(os.path.isabs(d) for d in x) else None),
        KwargInfo('exclude_directories', ContainerTypeInfo(list, str),
                  default=[], listify=True, since='0.42.0',
                  validator=lambda x: 'cannot be absolute' if any(os.path.isabs(d) for d in x) else None),
        INSTALL_MODE_KW.evolve(since='0.38.0'),
        INSTALL_TAG_KW.evolve(since='0.60.0'),
        INSTALL_FOLLOW_SYMLINKS,
    )
    def func_install_subdir(self, node: mparser.BaseNode, args: T.Tuple[str],
                            kwargs: 'kwtypes.FuncInstallSubdir') -> build.InstallDir:
        exclude = (set(kwargs['exclude_files']), set(kwargs['exclude_directories']))

        srcdir = os.path.join(self.environment.source_dir, self.subdir, args[0])
        if not os.path.isdir(srcdir) or not any(os.listdir(srcdir)):
            FeatureNew.single_use('install_subdir with empty directory', '0.47.0', self.subproject, location=node)
            FeatureDeprecated.single_use('install_subdir with empty directory', '0.60.0', self.subproject,
                                         'It worked by accident and is buggy. Use install_emptydir instead.', node)
        install_mode = self._warn_kwarg_install_mode_sticky(kwargs['install_mode'])

        idir_name = kwargs['install_dir']
        if isinstance(idir_name, P_OBJ.OptionString):
            idir_name = idir_name.optname

        idir = build.InstallDir(
            self.subdir,
            args[0],
            kwargs['install_dir'],
            idir_name,
            install_mode,
            exclude,
            kwargs['strip_directory'],
            self.subproject,
            install_tag=kwargs['install_tag'],
            follow_symlinks=kwargs['follow_symlinks'])
        self.build.install_dirs.append(idir)
        return idir

    @noPosargs
    @typed_kwargs(
        'configure_file',
        DEPFILE_KW.evolve(since='0.52.0'),
        INSTALL_MODE_KW.evolve(since='0.47.0,'),
        INSTALL_TAG_KW.evolve(since='0.60.0'),
        KwargInfo('capture', bool, default=False, since='0.41.0'),
        KwargInfo(
            'command',
            (ContainerTypeInfo(list, (build.Executable, ExternalProgram, compilers.Compiler, mesonlib.File, str), allow_empty=False), NoneType),
            listify=True,
        ),
        KwargInfo(
            'configuration',
            (ContainerTypeInfo(dict, (str, int, bool)), build.ConfigurationData, NoneType),
        ),
        KwargInfo(
            'copy', bool, default=False, since='0.47.0',
            deprecated='0.64.0', deprecated_message='Use fs.copyfile instead',
        ),
        KwargInfo('encoding', str, default='utf-8', since='0.47.0'),
        KwargInfo('format', str, default='meson', since='0.46.0',
                  validator=in_set_validator({'meson', 'cmake', 'cmake@'})),
        KwargInfo(
            'input',
            ContainerTypeInfo(list, (mesonlib.File, str)),
            listif
```
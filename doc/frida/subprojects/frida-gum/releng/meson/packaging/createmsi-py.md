Response:
Let's break down the thought process for analyzing this Python script.

**1. Understanding the Goal:**

The first thing is to read the docstring and initial comments. It clearly states the purpose: generating MSI packages for Windows. This immediately tells us the target operating system and the type of artifact being created.

**2. High-Level Overview of the Script's Structure:**

Next, I quickly scan the code to identify the main components:

* **Imports:**  Standard library modules like `subprocess`, `shutil`, `os`, `xml.etree.ElementTree`, and a local import `mesonbuild.coredata`. This gives clues about the operations involved (running commands, file manipulation, XML processing, accessing Meson's version).
* **`gen_guid()` function:**  A utility function for generating UUIDs, suggesting the MSI package will need unique identifiers.
* **`Node` class:** A simple data structure to represent directory and file information. This hints at how the file system will be traversed and organized for packaging.
* **`PackageGenerator` class:**  The core class containing the logic for building the MSI. This is where most of the analysis will focus.
* **`install_wix()` function:** A function to install the WiX toolset, indicating that this external tool is crucial for generating the MSI.
* **`if __name__ == '__main__':` block:** The entry point, handling setup, dependency checks, and invoking the `PackageGenerator`.

**3. Deep Dive into `PackageGenerator`:**

This is the heart of the script. I examine its methods one by one, focusing on what each does and how it relates to MSI packaging:

* **`__init__`:**  Initializes key variables: product name, manufacturer, version (obtained from `mesonbuild.coredata`), paths, GUIDs, and most importantly, sets up the staging directories (`dist`, `dist2`) and the feature properties. The handling of `redist_globs` is interesting; it's looking for Visual C++ runtime merge modules, a common requirement for applications built with MSVC.
* **`build_dist()`:**  This clearly uses PyInstaller to create standalone executables of `meson.py`. The staging directories are used to organize the output. The call to `self.del_infodirs` to remove `-info` directories is a specific workaround for WiX limitations.
* **`generate_files()`:**  This is where the WiX XML (`.wxs`) file is constructed. It builds the XML tree programmatically using `xml.etree.ElementTree`. The different elements (`Package`, `SummaryInformation`, `Launch`, `MajorUpgrade`, `Media`, `Directory`, `Merge`, `Feature`, `Component`, `File`) are standard WiX elements for defining the MSI package structure and contents. The `create_xml` and `build_features` methods are helpers for this process. The manual pretty-printing and CDATA addition are notable post-processing steps.
* **`build_features()`:**  Simplifies adding components to features in the WiX XML.
* **`create_xml()`:**  Recursively traverses the staging directories and creates the corresponding directory and file entries in the WiX XML. It also creates `Component` elements, grouping files together. The PATH environment variable modification within the first component is a standard MSI practice.
* **`build_package()`:**  This executes the `wix build` command, the actual WiX tool, to compile the `.wxs` file into an MSI.

**4. Connecting to Reverse Engineering, Binaries, Kernels, etc.:**

Now, I actively look for connections to the prompt's specific requirements:

* **Reverse Engineering:** The script itself isn't *doing* reverse engineering, but it's *packaging* the output of the Meson build system. Meson is used to build software, some of which might be involved in reverse engineering (e.g., debuggers, disassemblers). The *output* of Meson, packaged by this script, could be used for reverse engineering.
* **Binary/Low-Level:**  The use of PyInstaller inherently involves dealing with compiled binaries. The inclusion of the Visual C++ runtime (`.msm`) is directly related to the dependencies of the compiled Meson executable. MSI itself is a binary format.
* **Linux/Android Kernels/Frameworks:**  Directly, this script is for Windows. However, Meson is a cross-platform build system, so it *could* be used to build software targeting Linux or Android. This script is the Windows packaging step *after* the build.
* **Logical Reasoning:** The `create_xml` function uses recursion to map the directory structure to the XML. The conditional logic for including the Visual C++ runtime is another example. The assumption is that the staging directories contain the correct files and structure.
* **User/Programming Errors:**  Missing dependencies (PyInstaller, WiX), incorrect paths, malformed XML, and running the script in the wrong directory are potential errors.

**5. Generating Examples and Explanations:**

Based on the analysis, I create specific examples:

* **Reverse Engineering:**  Mentioning debuggers as potential output.
* **Binary/Low-Level:**  Explaining the `.msm` inclusion and the role of PyInstaller.
* **Linux/Android:**  Explaining Meson's cross-platform nature and the packaging context.
* **Logical Reasoning:**  Providing the `create_xml` recursion and the Visual C++ runtime condition as examples.
* **User Errors:**  Listing common mistakes and how they might manifest.
* **User Journey:**  Describing the steps to reach the script execution.

**6. Review and Refine:**

Finally, I review the generated explanation to ensure clarity, accuracy, and completeness, addressing all aspects of the prompt. I make sure the examples are concrete and easy to understand. I check if any crucial aspects were missed.

This iterative process of understanding the code's purpose, analyzing its structure and functions, connecting it to the prompt's requirements, generating examples, and reviewing the output leads to a comprehensive and informative explanation.
这是一个用于为 Windows 用户生成 MSI (Microsoft Installer) 包的 Python 脚本，它属于 Frida 动态插桩工具项目的一部分。以下是其功能的详细列表，以及与逆向、二进制底层、内核/框架知识、逻辑推理和常见错误的关联说明：

**主要功能：**

1. **构建用于 MSI 包的目录结构（Staging）：**
   - 使用 PyInstaller 将 `meson.py` 打包成独立的 Windows 可执行文件 (`meson.exe`)，并放置在 `dist` 目录下。
   - 将 `ninja.exe` (Ninja 构建工具的可执行文件) 复制到 `dist2` 目录下。
   - 这两个目录 (`dist` 和 `dist2`) 作为后续生成 MSI 包的临时“舞台”。

2. **生成 WiX 描述文件 (`meson.wxs`)：**
   - 使用 Python 的 `xml.etree.ElementTree` 库创建一个 XML 文件 (`meson.wxs`)，该文件遵循 WiX (Windows Installer XML Toolset) 的语法。
   - 这个 XML 文件描述了 MSI 包的内容、结构、安装过程和用户界面。
   - 它定义了：
     - 产品名称、制造商、版本号。
     - 升级代码 (UpgradeCode) 用于标识同一产品的不同版本。
     - 安装目录结构 (`ProgramFiles64Folder` -> `Meson`)。
     - 要安装的文件 (来自 `dist` 和 `dist2` 目录)。
     - 可选的功能 (Features)，例如 Meson 可执行文件和 Ninja 构建工具。
     - 依赖的 Visual C++ 运行时库的合并模块 (Merge Module)。
     - 用户界面元素 (使用 `ui:WixUI_FeatureTree`)。
     - 环境变量的设置 (将 Meson 的安装目录添加到 `PATH` 环境变量)。
     - 安装条件 (例如，只支持 Windows 10 或更高版本)。

3. **整合 Visual C++ 运行时库：**
   - 脚本会查找系统上安装的 Visual Studio 版本的 Visual C++ 运行时库的合并模块 (`.msm` 文件)。
   - 它会将这个合并模块添加到 MSI 包中，确保在没有安装相应 Visual C++ 运行时的情况下，Meson 也能正常运行。

4. **使用 WiX 工具集构建 MSI 包：**
   - 调用外部命令 `wix build`，使用生成的 `meson.wxs` 文件和许可证文件 (`packaging\\License.rtf`)，以及 WiX 工具集的扩展库，最终生成 MSI 安装包 (`meson-{version}-64.msi`)。

**与逆向方法的关联：**

* **打包用于逆向的工具：** Frida 本身是一个动态插桩工具，广泛用于软件逆向工程、安全分析和漏洞研究。这个脚本负责打包 Frida 的一部分（可能是构建系统本身），以便用户安装后可以使用 Frida 进行逆向分析。
* **分发逆向工具的依赖：**  逆向工具通常依赖一些底层的库和运行时环境。该脚本确保了 Visual C++ 运行时的正确分发，这是许多逆向工具（包括 Frida 的组件）运行的基础。

**举例说明：**  假设逆向工程师想要在 Windows 上使用 Frida 来分析某个程序。他们需要先安装 Frida。这个脚本生成的 MSI 包就是用户安装 Frida 的方式之一。安装完成后，他们可以使用 Frida 的各种功能，如 hook 函数、跟踪代码执行等，来进行逆向分析。

**涉及到二进制底层、Linux、Android 内核及框架的知识：**

* **二进制底层 (Windows)：**
    * **MSI 包格式：**  脚本生成的是 MSI 包，这是一种 Windows 平台上的二进制安装包格式。理解 MSI 的结构和工作原理有助于理解脚本的目的。
    * **可执行文件打包 (PyInstaller)：** PyInstaller 的工作原理是将 Python 代码及其依赖项打包成独立的二进制可执行文件。这涉及到对操作系统加载器、动态链接等底层机制的理解。
    * **Visual C++ 运行时：**  MSI 包中包含的 Visual C++ 运行时库是编译后的 C/C++ 代码运行所必需的。了解这些库的作用以及它们与二进制代码的链接方式是相关的。
    * **环境变量 (PATH)：** 脚本修改了系统的 `PATH` 环境变量，这直接影响到操作系统如何查找和执行可执行文件。

* **Linux/Android 内核及框架：**  虽然此脚本是为 Windows 构建 MSI 包，但 Frida 本身是一个跨平台的工具，可以用于 Linux 和 Android 平台的动态插桩。
    * **Frida 的跨平台性：** 理解 Frida 在不同平台上的架构和工作方式，有助于理解为什么需要构建针对不同平台的安装包。
    * **动态链接库：** 虽然 MSI 包主要针对 Windows，但动态链接库的概念在所有操作系统中都存在。Frida 在 Linux 和 Android 上也会以动态链接库的形式存在。
    * **内核交互：** Frida 的核心功能是动态插桩，这需要与目标进程的内存空间进行交互，甚至可能涉及到与操作系统内核的交互。理解这些底层的交互有助于理解 Frida 的功能。

**举例说明：**

* **二进制底层：** 脚本中使用了 `shutil.which('ninja')` 来查找 Ninja 可执行文件的路径。这涉及到操作系统如何查找可执行文件的底层机制。
* **Linux/Android 内核及框架：**  Frida 在 Android 上的工作原理涉及到与 Android Runtime (ART) 或 Dalvik 虚拟机的交互，以及可能的内核模块。虽然此脚本不直接处理 Android，但它所打包的 Frida 组件最终可能被用于 Android 平台的逆向分析。

**逻辑推理：**

* **假设输入：**
    * 脚本在 Meson 项目的源代码根目录下运行，并且存在 `meson.py` 文件。
    * 已经安装了 PyInstaller 和 WiX 工具集。
    * 系统上安装了 Visual Studio，并且可以找到相应的 Visual C++ 运行时库的合并模块。
* **输出：**
    * 在脚本执行的目录下生成一个名为 `meson-{version}-64.msi` 的 MSI 安装包。
    * 这个 MSI 包包含了 Meson 的可执行文件、Ninja 构建工具以及必要的 Visual C++ 运行时库。
    * 安装后，Meson 的可执行文件可以从命令行访问。

**用户或编程常见的使用错误：**

* **未安装依赖项：**
    * 错误信息：`ERROR: This script requires pyinstaller.` 或在 `build_package` 步骤中出现 `wix` 命令找不到的错误。
    * 解决方法：按照脚本中的 `install_wix()` 函数的提示或手动安装 PyInstaller 和 WiX Toolset。
* **在错误的目录下运行脚本：**
    * 错误信息：`Run me in the top level source dir.`
    * 解决方法：将终端切换到 Frida 项目的根目录，确保 `meson.py` 文件存在于当前目录。
* **找不到 Visual C++ 运行时库：**
    * 错误信息：`No MSMs found.`
    * 解决方法：检查是否安装了 Visual Studio，并且对应的 Visual C++ 生成工具集已安装。确认脚本中 `redist_globs` 的路径是否与系统上的实际路径匹配。
* **WiX XML 格式错误：**
    * 错误信息：`wix build` 命令报错，提示 XML 语法错误。
    * 解决方法：检查生成的 `meson.wxs` 文件，查看是否有格式不正确的地方，例如标签未闭合、属性值缺失等。
* **PyInstaller 打包失败：**
    * 错误信息：`subprocess.CalledProcessError` 在执行 PyInstaller 命令时抛出。
    * 解决方法：检查 `meson.py` 文件是否存在错误，或者 PyInstaller 的配置是否有问题。可以尝试手动运行 PyInstaller 命令进行调试。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户想要在 Windows 上安装 Frida。**
2. **他们可能从 Frida 的官方网站或 GitHub 仓库下载了源代码。**
3. **在阅读安装文档或构建指南后，他们了解到需要构建 MSI 安装包。**
4. **他们导航到 Frida 源代码目录下的 `frida/subprojects/frida-gum/releng/meson/packaging/` 目录。**
5. **他们找到了 `createmsi.py` 这个脚本。**
6. **他们打开终端或命令提示符，并切换到这个脚本所在的目录。**
7. **他们尝试运行脚本，通常使用命令 `python createmsi.py`。**

作为调试线索，如果用户在执行上述步骤时遇到问题，例如缺少依赖项或路径错误，这些信息可以帮助开发者定位问题。例如，如果用户报告 `wix` 命令找不到，开发者就知道问题可能出在 WiX 工具集的安装上。如果用户报告找不到 MSM 文件，开发者就需要检查 MSM 文件的查找逻辑和路径配置。

总而言之，`createmsi.py` 是 Frida 项目中一个关键的构建脚本，负责将 Meson 构建系统打包成 Windows 平台上的 MSI 安装包，方便用户安装和使用 Frida 这一强大的逆向工具。它涉及到操作系统底层机制、打包技术、构建工具链以及对目标平台的理解。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/releng/meson/packaging/createmsi.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2017-2021 The Meson development team

'''
This script is for generating MSI packages
for Windows users.
'''

import subprocess
import shutil
import uuid
import sys
import os
from glob import glob
import xml.etree.ElementTree as ET

sys.path.append(os.getcwd())
from mesonbuild import coredata

# Elementtree does not support CDATA. So hack it.
WINVER_CHECK = 'Installed OR (VersionNT64 &gt; 602)>'

def gen_guid():
    '''
       Generate guid
    '''
    return str(uuid.uuid4()).upper()

class Node:
    '''
       Node to hold path and directory values
    '''

    def __init__(self, dirs, files):
        self.check_dirs(dirs)
        self.check_files(files)
        self.dirs = dirs
        self.files = files

    @staticmethod
    def check_dirs(dirs):
        '''
           Check to see if directory is instance of list
        '''
        assert isinstance(dirs, list)

    @staticmethod
    def check_files(files):
        '''
           Check to see if files is instance of list
        '''
        assert isinstance(files, list)


class PackageGenerator:
    '''
       Package generator for MSI packages
    '''

    def __init__(self):
        self.product_name = 'Meson Build System'
        self.manufacturer = 'The Meson Development Team'
        self.version = coredata.version.replace('dev', '')
        self.root = None
        self.guid = '*'
        self.update_guid = '141527EE-E28A-4D14-97A4-92E6075D28B2'
        self.main_xml = 'meson.wxs'
        self.main_o = 'meson.wixobj'
        self.final_output = f'meson-{self.version}-64.msi'
        self.staging_dirs = ['dist', 'dist2']
        self.progfile_dir = 'ProgramFiles64Folder'
        redist_globs = ['C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Community\\VC\\Redist\\MSVC\\v*\\MergeModules\\Microsoft_VC142_CRT_x64.msm',
                        'C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Redist\\MSVC\\v*\\MergeModules\\Microsoft_VC143_CRT_x64.msm']
        redist_path = None
        for g in redist_globs:
            trials = glob(g)
            if len(trials) > 1:
                sys.exit('MSM glob matched multiple entries:' + '\n'.join(trials))
            if len(trials) == 1:
                redist_path = trials[0]
                break
        if redist_path is None:
            sys.exit('No MSMs found.')
        self.redist_path = redist_path
        self.component_num = 0
        self.feature_properties = {
            self.staging_dirs[0]: {
                'Id': 'MainProgram',
                'Title': 'Meson',
                'Description': 'Meson executables',
                'Level': '1',
                'AllowAbsent': 'no',
            },
            self.staging_dirs[1]: {
                'Id': 'NinjaProgram',
                'Title': 'Ninja',
                'Description': 'Ninja build tool',
                'Level': '1',
            }
        }
        self.feature_components = {}
        for s_d in self.staging_dirs:
            self.feature_components[s_d] = []

    def build_dist(self):
        '''
           Build dist file from PyInstaller info
        '''
        for sdir in self.staging_dirs:
            if os.path.exists(sdir):
                shutil.rmtree(sdir)
        main_stage, ninja_stage = self.staging_dirs

        pyinstaller = shutil.which('pyinstaller')
        if not pyinstaller:
            print("ERROR: This script requires pyinstaller.")
            sys.exit(1)

        pyinstaller_tmpdir = 'pyinst-tmp'
        if os.path.exists(pyinstaller_tmpdir):
            shutil.rmtree(pyinstaller_tmpdir)
        pyinst_cmd = [pyinstaller,
                      '--clean',
                      '--additional-hooks-dir=packaging',
                      '--distpath',
                      pyinstaller_tmpdir]
        pyinst_cmd += ['meson.py']
        subprocess.check_call(pyinst_cmd)
        shutil.move(pyinstaller_tmpdir + '/meson', main_stage)
        self.del_infodirs(main_stage)
        if not os.path.exists(os.path.join(main_stage, 'meson.exe')):
            sys.exit('Meson exe missing from staging dir.')
        os.mkdir(ninja_stage)
        shutil.copy(shutil.which('ninja'), ninja_stage)
        if not os.path.exists(os.path.join(ninja_stage, 'ninja.exe')):
            sys.exit('Ninja exe missing from staging dir.')

    def del_infodirs(self, dirname):
        # Starting with 3.9.something there are some
        # extra metadatadirs that have a hyphen in their
        # file names. This is a forbidden character in WiX
        # filenames so delete them.
        for d in glob(os.path.join(dirname, '*-info')):
            shutil.rmtree(d)

    def generate_files(self):
        '''
           Generate package files for MSI installer package
        '''
        self.root = ET.Element('Wix', {
            'xmlns': 'http://wixtoolset.org/schemas/v4/wxs',
            'xmlns:ui': 'http://wixtoolset.org/schemas/v4/wxs/ui'
        })

        package = ET.SubElement(self.root, 'Package', {
            'Name': self.product_name,
            'Manufacturer': 'The Meson Development Team',
            'UpgradeCode': self.update_guid,
            'Language': '1033',
            'Codepage':  '1252',
            'Version': self.version,
        })

        ET.SubElement(package, 'SummaryInformation', {
            'Keywords': 'Installer',
            'Description': f'Meson {self.version} installer',
            'Manufacturer': 'The Meson Development Team',
        })

        ET.SubElement(package,
                      'Launch',
                      {'Message': 'This application is only supported on Windows 10 or higher.',
                       'Condition': 'X'*len(WINVER_CHECK)})

        ET.SubElement(package, 'MajorUpgrade',
                      {'DowngradeErrorMessage':
                       'A newer version of Meson is already installed.'})

        ET.SubElement(package, 'Media', {
            'Id': '1',
            'Cabinet': 'meson.cab',
            'EmbedCab': 'yes',
        })
        targetdir = ET.SubElement(package, 'StandardDirectory', {
            'Id': 'ProgramFiles64Folder',
        })
        installdir = ET.SubElement(targetdir, 'Directory', {
            'Id': 'INSTALLDIR',
            'Name': 'Meson',
        })
        ET.SubElement(installdir, 'Merge', {
            'Id': 'VCRedist',
            'SourceFile': self.redist_path,
            'DiskId': '1',
            'Language': '0',
        })

        ET.SubElement(package, 'ui:WixUI', {
            'Id': 'WixUI_FeatureTree',
        })
        for s_d in self.staging_dirs:
            assert os.path.isdir(s_d)
        top_feature = ET.SubElement(package, 'Feature', {
            'Id': 'Complete',
            'Title': 'Meson ' + self.version,
            'Description': 'The complete package',
            'Display': 'expand',
            'Level': '1',
            'ConfigurableDirectory': 'INSTALLDIR',
        })
        for s_d in self.staging_dirs:
            nodes = {}
            for root, dirs, files in os.walk(s_d):
                cur_node = Node(dirs, files)
                nodes[root] = cur_node
            self.create_xml(nodes, s_d, installdir, s_d)
            self.build_features(top_feature, s_d)
        vcredist_feature = ET.SubElement(top_feature, 'Feature', {
            'Id': 'VCRedist',
            'Title': 'Visual C++ runtime',
            'AllowAdvertise': 'no',
            'Display': 'hidden',
            'Level': '1',
        })
        ET.SubElement(vcredist_feature, 'MergeRef', {'Id': 'VCRedist'})
        ET.ElementTree(self.root).write(self.main_xml, encoding='utf-8', xml_declaration=True)
        # ElementTree cannot do pretty-printing, so do it manually
        import xml.dom.minidom
        doc = xml.dom.minidom.parse(self.main_xml)
        with open(self.main_xml, 'w') as open_file:
            open_file.write(doc.toprettyxml())
        # One last fix, add CDATA.
        with open(self.main_xml) as open_file:
            data = open_file.read()
        data = data.replace('X'*len(WINVER_CHECK), WINVER_CHECK)
        with open(self.main_xml, 'w') as open_file:
            open_file.write(data)

    def build_features(self, top_feature, staging_dir):
        '''
           Generate build features
        '''
        feature = ET.SubElement(top_feature, 'Feature', self.feature_properties[staging_dir])
        for component_id in self.feature_components[staging_dir]:
            ET.SubElement(feature, 'ComponentRef', {
                'Id': component_id,
            })

    def create_xml(self, nodes, current_dir, parent_xml_node, staging_dir):
        '''
           Create XML file
        '''
        cur_node = nodes[current_dir]
        if cur_node.files:
            component_id = f'ApplicationFiles{self.component_num}'
            comp_xml_node = ET.SubElement(parent_xml_node, 'Component', {
                'Id': component_id,
                'Bitness': 'always64',
                'Guid': gen_guid(),
            })
            self.feature_components[staging_dir].append(component_id)
            if self.component_num == 0:
                ET.SubElement(comp_xml_node, 'Environment', {
                    'Id': 'Environment',
                    'Name': 'PATH',
                    'Part': 'last',
                    'System': 'yes',
                    'Action': 'set',
                    'Value': '[INSTALLDIR]',
                })
            self.component_num += 1
            for f_node in cur_node.files:
                file_id = os.path.join(current_dir, f_node).replace('\\', '_').replace('#', '_').replace('-', '_')
                ET.SubElement(comp_xml_node, 'File', {
                    'Id': file_id,
                    'Name': f_node,
                    'Source': os.path.join(current_dir, f_node),
                })

        for dirname in cur_node.dirs:
            dir_id = os.path.join(current_dir, dirname).replace('\\', '_').replace('/', '_').replace('-', '_')
            dir_node = ET.SubElement(parent_xml_node, 'Directory', {
                'Id': dir_id,
                'Name': dirname,
            })
            self.create_xml(nodes, os.path.join(current_dir, dirname), dir_node, staging_dir)

    def build_package(self):
        '''
           Generate the Meson build MSI package.
        '''
        subprocess.check_call(['wix',
                               'build',
                               '-bindvariable', 'WixUILicenseRtf=packaging\\License.rtf',
                               '-ext', 'WixToolset.UI.wixext',
                               '-culture', 'en-us',
                               '-arch', 'x64',
                               '-o',
                               self.final_output,
                               self.main_xml,
                               ])


def install_wix():
    subprocess.check_call(['dotnet',
                           'nuget',
                           'add',
                           'source',
                           'https://api.nuget.org/v3/index.json'])
    subprocess.check_call(['dotnet',
                           'tool',
                           'install',
                           '--global',
                           'wix'])
    subprocess.check_call(['wix',
                           'extension',
                           'add',
                           'WixToolset.UI.wixext',
                           ])

if __name__ == '__main__':
    if not os.path.exists('meson.py'):
        sys.exit(print('Run me in the top level source dir.'))
    if not shutil.which('wix'):
        install_wix()
    subprocess.check_call(['pip', 'install', '--upgrade', 'pyinstaller'])

    p = PackageGenerator()
    p.build_dist()
    p.generate_files()
    p.build_package()

"""

```
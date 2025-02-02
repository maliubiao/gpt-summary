import argparse
import json
import os
import shlex
import subprocess
import logging
import multiprocessing
from concurrent.futures import ThreadPoolExecutor, as_completed

def process_file(args, entry, extra_flags):
    directory = entry['directory']
    command = entry['command']
    source_file = entry['file']

    # 解析原始编译命令
    try:
        cmd_args = shlex.split(command)
    except ValueError as e:
        logging.warning(f"Skipping invalid command for {source_file}: {e}")
        return

    if not cmd_args:
        logging.warning(f"Empty command for {source_file}")
        return

    # 替换编译器为clang
    cmd_args[0] = args.clang_path

    # 过滤参数
    filtered_args = []
    skip_next = False
    for arg in cmd_args[1:]:
        if skip_next:
            skip_next = False
            continue
        if arg == '-c':
            continue
        elif arg == '-o':
            skip_next = True
            continue
        elif arg.startswith('-o'):
            continue
        elif arg.startswith('-Wp,-MMD') or arg.startswith('-Wp,-MD'):
            continue
        else:
            filtered_args.append(arg)

    # 确保源文件路径存在于参数中
    if source_file not in filtered_args:
        filtered_args.append(source_file)

    # 添加额外的CFLAGS
    filtered_args.extend(extra_flags)

    # 计算输出路径
    if os.path.isabs(source_file) and source_file.startswith(directory):
        abs_source_path = os.path.realpath(source_file)
    else:
        abs_source_path = os.path.realpath(os.path.join(directory, source_file))
        
    try:
        rel_source_path = os.path.relpath(abs_source_path, start=args.base_dir)
    except ValueError:
        logging.error(f"Source file {abs_source_path} is not under base directory {args.base_dir}")
        return

    preprocessed_path = os.path.join(args.output_dir, rel_source_path + '.pre.c')
    dep_path = os.path.join(args.output_dir, rel_source_path + '.d')

    # 创建输出目录
    os.makedirs(os.path.dirname(preprocessed_path), exist_ok=True)
    os.makedirs(os.path.dirname(dep_path), exist_ok=True)

    # 检查文件是否存在
    if not args.overwrite and os.path.exists(preprocessed_path):
        logging.info(f"Skipping existing file: {preprocessed_path}")
        return

    # 构建预处理命令
    preprocess_cmd = [
        args.clang_path,
        '-E',
        '-MD', '-MF', dep_path,
        '-Wno-unknown-warning-option',
        '-Wno-ignored-optimization-argument',
    ] + filtered_args

    # 执行预处理
    try:
        result = subprocess.run(
            preprocess_cmd,
            cwd=directory,
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError as e:
        logging.error(f"Preprocessing failed for {source_file}:\n{e.stderr}")
        return
    except Exception as e:
        logging.error(f"Unexpected error processing {source_file}: {e}")
        return

    # 写入预处理结果
    try:
        with open(preprocessed_path, 'w') as f:
            f.write(result.stdout)
        logging.info(f"Generated preprocessed file: {preprocessed_path}")
    except IOError as e:
        logging.error(f"Failed to write {preprocessed_path}: {e}")

    # 验证依赖文件
    if not os.path.exists(dep_path):
        logging.warning(f"Dependency file not generated: {dep_path}")

def main():
    parser = argparse.ArgumentParser(description='Preprocess source files with clang to expand macros and track header dependencies.')
    parser.add_argument('--compile-commands', default='compile_commands.json',
                        help='Path to compile_commands.json (default: compile_commands.json)')
    parser.add_argument('--output-dir', required=True,
                        help='Output directory for preprocessed files and dependencies')
    parser.add_argument('--base-dir', required=True,
                        help='Base directory to construct relative paths for output files')
    parser.add_argument('--clang-path', default='clang',
                        help='Path to the clang compiler (default: clang)')
    parser.add_argument('--overwrite', action='store_true',
                        help='Overwrite existing files')
    parser.add_argument('--verbose', action='store_true',
                        help='Enable verbose logging')
    parser.add_argument('--extra-cflags', default='',
                        help='Additional CFLAGS to include in preprocessing')
    parser.add_argument('--workers', type=int, default=0,
                        help='Number of parallel workers (0 for auto, 1 for sequential)')
    args = parser.parse_args()

    # 配置日志
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(levelname)s: %(message)s'
    )

    # 读取compile_commands.json
    try:
        with open(args.compile_commands, 'r') as f:
            compile_commands = json.load(f)
    except Exception as e:
        logging.error(f"Failed to read compile_commands.json: {e}")
        return

    # 解析额外的CFLAGS
    extra_flags = []
    if args.extra_cflags:
        try:
            extra_flags = shlex.split(args.extra_cflags)
            # 检查-I参数对应的目录是否存在
            i = 0
            while i < len(extra_flags):
                if extra_flags[i] == '-I':
                    include_dir = extra_flags[i+1]
                    if not os.path.isdir(include_dir):
                        logging.warning(f"Include directory not found: {include_dir}")
                    i += 2
                else:
                    i += 1
            logging.info(f"Using extra CFLAGS: {extra_flags}")
        except Exception as e:
            logging.warning(f"Failed to parse extra CFLAGS: {e}")

    # 确定worker数量
    if args.workers == 0:
        workers = min(32, (multiprocessing.cpu_count() or 1) * 2)
    elif args.workers == 1:
        # 顺序执行
        for entry in compile_commands:
            process_file(args, entry, extra_flags)
        return
    else:
        workers = args.workers

    # 使用线程池并行处理
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [
            executor.submit(process_file, args, entry, extra_flags)
            for entry in compile_commands
        ]
        
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                logging.error(f"Error in worker: {e}")

if __name__ == '__main__':
    main()

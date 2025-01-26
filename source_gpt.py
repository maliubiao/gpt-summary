import os
import argparse
import pdb
import asyncio
from gpt_lsp import AsyncOpenAIClient, add_arguments
from markdown_syntax_map import get_language_identifier,syntax_map

def read_prompt_template(prompt_template_path):
    """读取提示词模板文件"""
    with open(prompt_template_path, 'r', encoding='utf-8') as f:
        return f.read()

def should_skip_file(file_path, exclude_dirs, file_suffixes):
    """判断是否应该跳过当前文件"""
    if any(exclude_dir in file_path.split(os.sep) for exclude_dir in exclude_dirs):
        return True
    if "gay-" in os.path.basename(file_path) or "_tests" in file_path:
        return True
    if not any(file_path.endswith(suffix) for suffix in file_suffixes):
        return True
    return False

def process_file_content(file_path, directory, chunk_size=32*1024):
    """处理文件内容，返回文件信息和分块内容"""
    relative_path = os.path.relpath(file_path, directory)
    dir_last_part = os.path.basename(os.path.normpath(directory))
    modified_relative_path = os.path.join(dir_last_part, relative_path)
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        file_content = f.read()

    if len(file_content) > chunk_size:
        chunks = [file_content[i:i + chunk_size] for i in range(0, len(file_content), chunk_size)]
        return [
            (modified_relative_path,
             f"这是第{i+1}部分，共{len(chunks)}部分，请归纳一下它的功能\n",
             chunk, "\n", i)
            for i, chunk in enumerate(chunks)
        ]
    else:
        return [(modified_relative_path, "", file_content, "", 0)]

def generate_output_path(output_dir, filepath, idx, file_suffix):
    """优化后的路径生成"""
    base_name = os.path.splitext(os.path.basename(filepath))[0]
    output_base = os.path.join(output_dir, os.path.dirname(filepath), base_name)
    return f"{output_base}-{file_suffix}-{idx}.md" if idx > 0 else f"{output_base}-{file_suffix}.md"

async def handle_streaming_response(prompt, output_file_path=None):
    """通用流式响应处理函数"""
    reasoning = ""
    response_text = ""
    
    async for tp, token in openai_client.ask_stream(prompt):
        if tp == openai_client.type_reasoning:
            reasoning += token
        else:
            response_text += token
    
    markdown_content = generate_markdown_content(reasoning, response_text, prompt)
    
    if output_file_path:
        save_markdown_file(output_file_path, markdown_content)
    
    return markdown_content

def generate_markdown_content(reasoning, response_text, prompt):
    """生成Markdown内容"""
    # Get file extension and use it to determine language identifier
    return (
        f"响应:\n\n```\n{reasoning}\n```\n{response_text}\n"
        f"提示器:\n\n{prompt}\n"
    )

def save_markdown_file(output_file_path, content):
    """保存Markdown文件"""
    os.makedirs(os.path.dirname(output_file_path), exist_ok=True)
    with open(output_file_path, 'w', encoding='utf-8') as f:
        f.write(content)

async def stream_response(prompt, output_file_path):
    """流式处理响应并保存结果（调用公共函数）"""
    await handle_streaming_response(prompt, output_file_path)

async def process_single_file(file_info, prompt_template, output_dir):
    """处理单个文件"""
    filepath, prefix, file_content, suffix, idx = file_info
    file_suffix = os.path.splitext(filepath)[1].strip(".")
    ext = os.path.splitext(filepath)[1]
    prompt = prompt_template.format(
        filepath=filepath,
        prefix=prefix,
        file_content=file_content,
        suffix=suffix,
        lang=get_language_identifier(ext)
    )
    output_file_path = generate_output_path(output_dir, filepath, idx, file_suffix)
    print(output_file_path)
    if os.path.exists(output_file_path):
        logger.info(f"已经存在{output_file_path}")
        return

    try:
        await stream_response(prompt, output_file_path)
    except ValueError:
        pass

async def generate_file_list_and_content(directory, prompt_template_path, output_dir, file_suffixes, exclude_dirs):
    """主函数：生成文件列表并处理内容"""
    prompt_template = read_prompt_template(prompt_template_path)

    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            if should_skip_file(file_path, exclude_dirs, file_suffixes):
                continue

            file_infos = process_file_content(file_path, directory)
            for file_info in file_infos:
                await process_single_file(file_info, prompt_template, output_dir)

async def main():
    global openai_client,logger
    import logging
    logger = logging.getLogger(__name__)
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s - Line: %(lineno)d')

    parser = argparse.ArgumentParser(description="Generate prompts for source files in a directory.")
    parser.add_argument('--dir', required=True, help='Directory to walk')
    parser.add_argument('--prompt-template', required=True, help='Path to the prompt template file')
    parser.add_argument('--output-dir', default="src", help='Output directory for generated files')
    parser.add_argument('--file-suffixes', nargs='+', default=['.go', ".cc"], help='List of file suffixes to filter source files')
    parser.add_argument('--exclude', nargs='+', default=[], help='List of directories to exclude')
    add_arguments(parser)
    args = parser.parse_args()

    openai_client = AsyncOpenAIClient(
        args.api_base,
        args.model_name,
        args.api_token,
        args.gemini,
        args.gemini_token,
        args.gemini_model
    )
    test_markdown = await handle_streaming_response("hello")
    print(test_markdown)
    await generate_file_list_and_content(args.dir, args.prompt_template, args.output_dir, args.file_suffixes, args.exclude)

if __name__ == "__main__":
    asyncio.run(main())

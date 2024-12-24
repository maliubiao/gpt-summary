import os
import argparse
import pdb
import asyncio
from gpt_lsp import AsyncOpenAIClient, add_arguments

def generate_file_list_and_content(directory, prompt_template_path, output_dir, file_suffixes):
    with open(prompt_template_path, 'r', encoding='utf-8') as f:
        prompt_template = f.read()
    for root, _, files in os.walk(directory):
        for file in files:
            if any(file.endswith(suffix) for suffix in file_suffixes):
                if "gay-" in file: 
                    continue
                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, directory)
                # 获取目录的最后一部分
                dir_last_part = os.path.basename(os.path.normpath(directory))
                # 将目录的最后一部分添加到相对路径中
                modified_relative_path = os.path.join(dir_last_part, relative_path)
                with open(file_path, 'r', encoding='utf-8') as f:
                    file_content = f.read()
                file_list = []
                if len(file_content) > 64 * 1024:
                    # Split the file content into chunks of 64k
                    chunks = [file_content[i:i + 64 * 1024] for i in range(0, len(file_content), 64 * 1024)]
                    for i, chunk in enumerate(chunks):
                        prefix = f"这是第{i+1}部分，共{len(chunks)}部分，请归纳一下它的功能\n"
                        suffix = "\n"
                        file_list.append((modified_relative_path, prefix, chunk, suffix, i))
                else:
                    prefix = ""
                    suffix = ""
                    file_list.append((modified_relative_path, prefix, file_content, suffix, 0))

                for filepath, prefix, file_content, suffix, idx in file_list:
                    prompt = (prompt_template.format(filepath=filepath, prefix=prefix, file_content=file_content, suffix=suffix))
                    base_output_file_path = os.path.join(output_dir, os.path.splitext(modified_relative_path)[0] + ".md")
                    output_file_path = base_output_file_path
                    if idx == 0 and os.path.exists(output_file_path):
                        logger.info(f"已经存在{output_file_path}")
                        continue
                    if idx > 0:
                        base_output_file_path = os.path.join(output_dir, os.path.splitext(modified_relative_path)[0] + "-%d.md" % idx)
                        output_file_path = base_output_file_path
                        if os.path.exists(output_file_path):
                            logger.info(f"已经存在{output_file_path}")
                            continue
                    async def stream_response(prompt):
                        response_text = ""
                        async for chunk in openai_client.ask_stream(prompt):
                            print(chunk)
                            response_text += chunk
                        markdown_content = f"Response: {response_text}\nPrompt: \n```\n{prompt}\n```"
                        os.makedirs(os.path.dirname(output_file_path), exist_ok=True)
                        with open(output_file_path, 'w', encoding='utf-8') as f:
                            f.write(markdown_content)
                    asyncio.run(stream_response(prompt))



if __name__ == "__main__":

    import logging
    logger = logging.getLogger(__name__)
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s - Line: %(lineno)d')

    parser = argparse.ArgumentParser(description="Generate prompts for source files in a directory.")
    parser.add_argument('--dir', required=True, help='Directory to walk')
    parser.add_argument('--prompt-template', required=True, help='Path to the prompt template file')
    parser.add_argument('--output-dir', default="src", help='Output directory for generated files')
    parser.add_argument('--file-suffixes', nargs='+', default=['.go', ".cc"], help='List of file suffixes to filter source files')
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
    test_response = asyncio.run(openai_client.ask("hello"))
    # logger.info(f"Test response from LLM: {test_response}")
    # pdb.set_trace()
    generate_file_list_and_content(args.dir, args.prompt_template, args.output_dir, args.file_suffixes)

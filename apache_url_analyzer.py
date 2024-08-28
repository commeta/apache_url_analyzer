#!/usr/bin/env python3

import os
import tempfile

LOG_FILES_GLOB = "/etc/httpd/sites/*/*.conf"

def get_log_files():
    grep_command = f"grep -r 'CustomLog' {LOG_FILES_GLOB} | awk -F'CustomLog ' '{{print $2}}' | awk '{{print $1}}'"
    log_files = os.popen(grep_command).read().splitlines()
    return log_files

def process_log_files(log_type, keyword, output_file):
    temp_file = tempfile.NamedTemporaryFile(delete=False)
    temp_filename = temp_file.name
    log_files = get_log_files()
    for log_file in log_files:
        if os.path.isfile(log_file):
            with open(log_file, 'r') as file:
                for log_line in file:
                    if keyword in log_line:
                        parts = log_line.split()
                        url = parts[6]
                        # Отбрасываем параметры запроса
                        url = url.split('?')[0]
                        # Извлечение домена из имени файла
                        base_name = os.path.basename(log_file)
                        domain = base_name.rsplit('-', 1)[0]  # Отбрасываем последнюю часть после последнего "-"
                        temp_file.write(f"{domain} {url}\n".encode())
    temp_file.close()
    if os.path.isfile(output_file):
        with open(output_file, 'r') as file:
            with open(temp_filename, 'ab') as temp_file_append:
                temp_file_append.write(file.read().encode())
              
    unique_urls = set()
    with open(temp_filename, 'r') as file:
        unique_urls.update(file.readlines())
    with open(output_file, 'w') as file:
        file.writelines(sorted(unique_urls))
    os.remove(temp_filename)

if __name__ == "__main__":
    process_log_files('POST', 'POST', '/var/log/httpd/sites_post.log')
    process_log_files('DELETE', 'DELETE', '/var/log/httpd/sites_delete.log')
    process_log_files('PUT', 'PUT', '/var/log/httpd/sites_put.log')
    process_log_files('HEAD', 'HEAD', '/var/log/httpd/sites_head.log')

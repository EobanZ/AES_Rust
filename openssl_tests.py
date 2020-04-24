# Test-Framework for OpenSSL Command Line Tool

import sys
import os
import time
import subprocess
import re
import secrets
from tqdm import tqdm

# Get global heap maximum
def get_global_heap_max(result_file):
    test_name = 'Global Heap Maximum Test'
    print('--- Performing >>', test_name, '<< ...')
    # Test parameters
    filesizes     = [1024, 1024*1024, 1024*1024*1024]
    test_in_file  = 'dhat-test.tmp'
    test_out_file = 'dhat-test.out.tmp'
    key_128 = ''.join('{:02x}'.format(x) for x in secrets.token_bytes(16))
    key_256 = ''.join('{:02x}'.format(x) for x in secrets.token_bytes(32))
    iv      = ''.join('{:02x}'.format(x) for x in secrets.token_bytes(16))
    commands      = [
        'openssl enc -aes-128-ctr -K ' + key_128 + ' -iv ' + iv + ' -in ' + test_in_file + ' -out ' + test_out_file,
        'openssl enc -d -aes-128-ctr -K ' + key_128 + ' -iv ' + iv + ' -in ' + test_in_file + ' -out ' + test_out_file,
        'openssl enc -aes-256-ctr -K ' + key_256 + ' -iv ' + iv + ' -in ' + test_in_file + ' -out ' + test_out_file,
        'openssl enc -d -aes-256-ctr -K ' + key_256 + ' -iv ' + iv + ' -in ' + test_in_file + ' -out ' + test_out_file,
        ]
    # Loop through tests with different file sizes and commands
    with tqdm(total=len(filesizes)*len(commands)) as pbar:
        for filesize in filesizes:
            for cmd in commands:
                aes_key_len = re.search('aes-([0-9][0-9][0-9])-ctr', cmd).group(1)
                encrypt_decrypt = re.search('openssl\s(.*)\s-aes', cmd).group(1)
                # Initialize random test data
                subprocess.run(['openssl', 'rand', '-out', test_in_file, str(filesize)])
                # Call valgrind
                valgrind = subprocess.run(['valgrind', '--tool=dhat', '--dhat-out-file=dhat-output.tmp'] + cmd.split(' '),
                                           cwd='./', capture_output=True, text=True)
                global_heap_max = re.sub(',', '',  re.search('At.t-gmax:.(\d+|\d{1,3}(,\d{3})*)\s', valgrind.stderr).group(1))
                # Write result to file
                result_file.write(test_name + ', AES-' + aes_key_len + '-CTR '
                                  + encrypt_decrypt + ' ' + str(filesize) + ' bytes, '
                                  + global_heap_max + ', ' + cmd + '\n')
                # Remove temporary files
                subprocess.run(['rm', 'dhat-output.tmp'], cwd='./', capture_output=True, text=True)
                subprocess.run(['rm', test_in_file], cwd='./', capture_output=True, text=True)
                subprocess.run(['rm', test_out_file], cwd='./', capture_output=True, text=True)
                pbar.update(1)

# Get exection time
def get_execution_time(result_file):
    test_name = 'Execution Time Test'
    print('--- Performing >>', test_name, '<< ...')
    # Get rights to use perf counters, if necessary
    cat = subprocess.run(['cat', '/proc/sys/kernel/perf_event_paranoid'], capture_output=True, text=True)
    if cat.stdout.rstrip() != '0' and cat.stdout.rstrip() != '-1':
        os.system('sudo -S sh -c \'echo 0 > /proc/sys/kernel/perf_event_paranoid\'')
    # Test parameters
    filesizes     = [1024, 1024*1024, 1024*1024*1024]
    test_in_file  = 'perf-test.tmp'
    test_out_file = 'perf-test.out.tmp'
    key_128 = ''.join('{:02x}'.format(x) for x in secrets.token_bytes(16))
    key_256 = ''.join('{:02x}'.format(x) for x in secrets.token_bytes(32))
    iv      = ''.join('{:02x}'.format(x) for x in secrets.token_bytes(16))
    commands      = [
        'openssl enc -aes-128-ctr -K ' + key_128 + ' -iv ' + iv + ' -in ' + test_in_file + ' -out ' + test_out_file,
        'openssl enc -d -aes-128-ctr -K ' + key_128 + ' -iv ' + iv + ' -in ' + test_in_file + ' -out ' + test_out_file,
        'openssl enc -aes-256-ctr -K ' + key_256 + ' -iv ' + iv + ' -in ' + test_in_file + ' -out ' + test_out_file,
        'openssl enc -d -aes-256-ctr -K ' + key_256 + ' -iv ' + iv + ' -in ' + test_in_file + ' -out ' + test_out_file,
        ]
    n_measurements = 16
    # Loop through tests with different file sizes and commands
    with tqdm(total=len(filesizes)*len(commands)*n_measurements) as pbar:
        for filesize in filesizes:
            for cmd in commands:
                aes_key_len = re.search('aes-([0-9][0-9][0-9])-ctr', cmd).group(1)
                encrypt_decrypt = re.search('openssl\s(.*)\s-aes', cmd).group(1)
                time_data = []
                # Loop through several measurement runs
                for n in range(n_measurements):
                    # Initialize random test data
                    subprocess.run(['openssl', 'rand', '-out', test_in_file, str(filesize)])
                    # Call perf
                    perf = subprocess.run(['perf', 'stat'] + cmd.split(' '), cwd='./', capture_output=True, text=True)
                    time_str = re.sub(',', '.', re.search('([0-9]*,[0-9]*).seconds.time', perf.stderr).group(1))
                    time_float = float(time_str)
                    time_data.append(time_float)
                    # Remove temporary files
                    subprocess.run(['rm', test_in_file], cwd='./', capture_output=True, text=True)
                    subprocess.run(['rm', test_out_file], cwd='./', capture_output=True, text=True)
                    # Write iteration result to file
                    result_file.write(test_name + ', AES-' + aes_key_len + '-CTR '
                                      + encrypt_decrypt + ' ' + str(filesize) + ' bytes Test ' + str(n) + ', '
                                      + str(time_float) + ', ' + cmd + '\n')
                    pbar.update(1)
                # Write results to file
                result_file.write(test_name + ', AES-' + aes_key_len + '-CTR '
                                  + encrypt_decrypt + ' ' + str(filesize) + ' bytes MIN, '
                                  + str(min(time_data)) + ', ' + cmd + '\n')
                result_file.write(test_name + ', AES-' + aes_key_len + '-CTR '
                                  + encrypt_decrypt + ' ' + str(filesize) + ' bytes MAX, '
                                  + str(max(time_data)) + ', ' + cmd + '\n')
                result_file.write(test_name + ', AES-' + aes_key_len + '-CTR '
                                  + encrypt_decrypt + ' ' + str(filesize) + ' bytes AVG, '
                                  + str(sum(time_data)/len(time_data)) + ', ' + cmd + '\n')

# Print usage
def print_usage():
    print()
    print('Usage:')
    print('  ', sys.argv[0], '<path-to-result-file>')
    print()

# Main function
def main():

    # List of tests
    list_of_tests = [
        get_global_heap_max,
        get_execution_time,
        ]

    # Check command line arguments
    if len(sys.argv) != 2:
        print('!!! ERROR: Number of arguments does not match!')
        print_usage()
        sys.exit(1)

    # Check result file path    
    result_file_path = sys.argv[1]
    try:
        result_file = open(result_file_path, 'w')
        result_file.write('Test, Result Name, Result Value, Comment\n')
    except OSError:
        print('!!! ERROR: Cannot open result file for writing!')
        print_usage()
        sys.exit(1)
    
    # Perform tests
    local_time = time.ctime(time.time())
    print('### Starting Test Procedures (' + local_time + ') ...')
    for test in list_of_tests:
        test(result_file)
    local_time = time.ctime(time.time())
    print('### Finished Testing! (' + local_time + ')')

    # Close result file
    result_file.close()

if __name__ == "__main__":
    main()


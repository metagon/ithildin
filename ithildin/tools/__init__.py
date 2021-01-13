import os

ithildin_dir_name = '.ithildin'
ithildin_home = os.path.join(os.path.expanduser('~'), ithildin_dir_name)

benchmark_state_file = 'benchmark_state.json'
benchmark_state_path = os.path.join(ithildin_home, benchmark_state_file)

# Create .ithildin home directory if it doesn't exist
if not os.path.exists(ithildin_home):
    os.mkdir(ithildin_home)

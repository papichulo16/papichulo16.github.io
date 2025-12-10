FROM tjoconnor/bin-hosting

RUN apt-get update -qq -y && apt-get -qq -y install gdb git python3 python3-pip python3-dev git libssl-dev libffi-dev build-essential python3-pwntools tmux
RUN git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh

COPY pwntemplate.py /local.py
COPY solve_remote.py /remote.py
COPY jungle.bin_patched /chal
COPY libc.so.6 /libc.so.6
COPY ld-2.39.so /ld-2.39.so

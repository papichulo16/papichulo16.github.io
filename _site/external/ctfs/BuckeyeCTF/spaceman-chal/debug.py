import gdb
import subprocess

binary = "spaceman"

gdb.execute(f"file {binary}")
gdb.execute("set architecture riscv:rv64")
gdb.execute("target remote localhost:1234")


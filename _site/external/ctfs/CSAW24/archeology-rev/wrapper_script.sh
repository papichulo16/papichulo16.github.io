./generate_gdb.sh $1 > tmp.gdb; gdb -x tmp.gdb --batch 2>/dev/null| grep 0000555555558040


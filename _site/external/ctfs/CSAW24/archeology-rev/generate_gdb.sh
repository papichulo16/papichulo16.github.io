echo file archeology
echo b main
echo r test
echo b *0x00005555555557e8
echo b *0x0000555555555aa6
echo c
echo set *0x7fffffffe23f=0x54415000$1
echo c
echo dq \&memory


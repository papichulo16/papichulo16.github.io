echo "sun{aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}" > palatinepackflag.txt
clear
./palatinepack
xxd -p  flag.txt > a
xxd -p _flag.txt > b
difft a b
rm a b


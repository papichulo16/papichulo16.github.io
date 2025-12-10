function DoubleToIEEE(f)
{
    var buf = new ArrayBuffer(8);
    (new Float64Array(buf))[0] = f;
    return "0x" + (new Uint32Array(buf))[0].toString(16) + "" +(new Uint32Array(buf))[1].toString(16);
}

let a = function() { return 123; }
let b = [a];

b.confuse()
console.log(DoubleToIEEE(b[0]))


/*
let a = ["BBAA"];
let b = ["hello", "yur"];

console.log(a);
a.confuse();
console.log(DoubleToIEEE(a[0]));
a[0] += 0.001;
a.confuse();
console.log(a[0]);

b.confuse();
console.log(DoubleToIEEE(b[0]));
console.log(DoubleToIEEE(b[1]));

console.log("\nTrying double arr:");
let c = [12.34]

console.log(c);
console.log(DoubleToIEEE(c));
c.confuse();
console.log(DoubleToIEEE(c[0]));
c[0] = "AAAAAAAA";
c.confuse();
console.log(DoubleToIEEE(c[0]));
*/

/*
let a = ["AAAA", "BBBB"];

console.log(a);
a.confuse();
console.log(a);
a[1] = a[0];
console.log(a);
a.confuse();
console.log(a);
*/

/*
for (let i = 0; i < 20; i++) {
  a.confuse();
  a[0] += 8;
  a.confuse();
  console.log(a);
  a.confuse();
  a[0] -= 8;
  a.confuse();
  console.log(a);
}
*/

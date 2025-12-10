let num = 12.22;
let buffer = new ArrayBuffer(8);  // 8 bytes for a double (64-bit)
let view = new DataView(buffer);
view.setFloat64(0, num);  // Write the number as a double at byte position 0

let byteArray = [];
for (let i = 0; i < 8; i++) {
    byteArray.push(view.getUint8(i).toString(16));  // Read the bytes one by one
}

console.log(byteArray.join(""));

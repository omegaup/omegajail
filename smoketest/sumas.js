const readline = require("node:readline");

const rl = readline.createInterface({
  input: process.stdin,
});

rl.on("line", (input) => {
  console.log(
    input
      .trim()
      .split(" ")
      .map((x) => parseInt(x))
      .reduce((acc, x) => acc + x, 0)
  );
});

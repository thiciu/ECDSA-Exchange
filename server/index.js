const express = require('express');
const app = express();
const cors = require('cors');
const port = 3042;
const EC = require('elliptic').ec;
const SHA256 = require('crypto-js/sha256');

// localhost can have cross origin errors
// depending on the browser you use!
app.use(cors());
app.use(express.json());

const ec = new EC('secp256k1');
const key1 = ec.genKeyPair();
const key2 = ec.genKeyPair();
const key3 = ec.genKeyPair();
// encode the entire public key as a hexadecimal string
let publicKey1 = key1.getPublic().encode('hex');
let publicKey2 = key2.getPublic().encode('hex');
let publicKey3 = key3.getPublic().encode('hex');
publicKey1 = "0x" + publicKey1.slice(publicKey1.length - 40);
publicKey2 = "0x" + publicKey2.slice(publicKey2.length - 40);
publicKey3 = "0x" + publicKey3.slice(publicKey3.length - 40);

const privateKey1 = key1.getPrivate().toString(16);
const privateKey2 = key2.getPrivate().toString(16);
const privateKey3 = key3.getPrivate().toString(16);


const balances = {
  [publicKey1]: 100,
  [publicKey2]: 50,
  [publicKey3]: 75,
}

app.get('/balance/:address', (req, res) => {
  const {address} = req.params;
  const balance = balances[address] || 0;
  res.send({ balance });
});

function verifySig(sender, recipient, amount, r, s, recoveryParam) {
  const msg = JSON.stringify({
    to: recipient,
    amount: amount
  });
  const msgHash = SHA256(msg).toString();

  const signature = {r, s};
  let hexToDecimal = (x) => ec.keyFromPrivate(x, "hex").getPrivate().toString(10);
  let publicKey = ec.recoverPubKey(hexToDecimal(msgHash), signature, recoveryParam, "hex").encode("hex");
  publicKey = '0x' + publicKey.slice(-40);

  return (publicKey === sender);
}

app.post('/send', (req, res) => {
  const {sender, recipient, amount, r, s, recoveryParam} = req.body;
  if (verifySig(sender, recipient, Number(amount), r, s, Number(recoveryParam))) {
    if (sender in balances) {
      balances[sender] -= amount;
      balances[recipient] = (balances[recipient] || 0) + +amount;
      logBalance();
    }
    else {
      console.log("\nAccount doesn't exist.");
    }
  }
  else {
    console.log("\nUnmatching signature.");
  }
  res.send({ balance: balances[sender] });
});

function logBalance() {
  console.log("\nCurrent Balance\n==================");
  console.log(`(1) ${publicKey1} (${balances[publicKey1]})`);
  console.log(`(2) ${publicKey2} (${balances[publicKey2]})`);
  console.log(`(3) ${publicKey3} (${balances[publicKey3]})`);
}

function logAccounts() {
  console.log("Available Accounts\n==================");
  console.log(`(1) ${publicKey1} (${balances[publicKey1]})`);
  console.log(`(2) ${publicKey2} (${balances[publicKey2]})`);
  console.log(`(3) ${publicKey3} (${balances[publicKey3]})`);

  console.log("\nPrivate Keys\n==================");
  console.log(`(1) ${privateKey1}`);
  console.log(`(2) ${privateKey2}`);
  console.log(`(3) ${privateKey3}`);
}

app.listen(port, () => {
  console.log(`Listening on port ${port}!`);
  logAccounts();

});

const SHA256 = require('crypto-js/sha256');
const EC = require('elliptic').ec

const ec = new EC('secp256k1');

const privateKey = process.argv[2];
const key = ec.keyFromPrivate(privateKey);

const recipient = process.argv[3];

const amount = Number(process.argv[4]);

const msg = JSON.stringify({
	to: recipient,
	amount: amount
});

const msgHash = SHA256(msg);
const signature = key.sign(msgHash.toString());


console.log({
  message: msg,
  signature: {
    r: signature.r.toString(16),
    s: signature.s.toString(16),
    recoveryParam: signature.recoveryParam
  }
});
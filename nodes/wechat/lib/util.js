var crypto = require('crypto');

function checkSignature(signature, token, timestamp, nonce) {
	var shasum = crypto.createHash('sha1');
	var myArray = [timestamp, token, nonce];
	myArray = myArray.sort();
	var myString = myArray.join('');
	shasum.update(myString);
	var d = shasum.digest('hex');
	// console.log(d);
	if (d == signature) {
		return true;
	} else {
		return false;
	}
};

function PKCS7EncoderDecode(text) {
	var pad = text[text.length - 1];
	if (pad < 1 || pad > 32) {
		pad = 0;
	}
	return text.slice(0, text.length - pad);
};

function PKCS7EncoderEncode(text) {
	var blockSize = 32;
	var textLength = text.length;
	var amountToPad = blockSize - (textLength % blockSize);
	var result = new Buffer(amountToPad);
	result.fill(amountToPad);
	return Buffer.concat([text, result]);
};

function decrypt(text, encodingAESKey) {
	var key = new Buffer(encodingAESKey + '=', 'base64');
	var iv = key.slice(0, 16);
	var decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
	decipher.setAutoPadding(false);
	var deciphered = Buffer.concat([decipher.update(text, 'base64'), decipher.final()]);
	deciphered = PKCS7EncoderDecode(deciphered);
	var content = deciphered.slice(16);
	var length = content.slice(0, 4).readUInt32BE(0);
	return {
		message: content.slice(4, length + 4).toString(),
		id: content.slice(length + 4).toString()
	};
};

function encrypt(text, encodingAESKey) {
	var key = new Buffer(encodingAESKey + '=', 'base64');
	var iv = key.slice(0, 16);
	var randomString = crypto.pseudoRandomBytes(16);
	var msg = new Buffer(text);
	var msgLength = new Buffer(4);
	msgLength.writeUInt32BE(msg.length, 0);
	var id = new Buffer(this.id);
	var bufMsg = Buffer.concat([randomString, msgLength, msg, id]);
	var encoded = PKCS7EncoderEncode(bufMsg);
	var cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
	cipher.setAutoPadding(false);
	var cipheredMsg = Buffer.concat([cipher.update(encoded), cipher.final()]);
	return cipheredMsg.toString('base64');
};


var utils = {
	checkSignature: checkSignature,
	decrypt: decrypt,
	encrypt: encrypt
}

module.exports = utils;
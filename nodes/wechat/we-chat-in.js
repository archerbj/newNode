module.exports = function(RED) {
	"use strict";
	var http = require('http');
	var crypto = require('crypto');
	var bodyParser = require('body-parser');
	var getBody = require('raw-body');
	var cors = require('cors');
	var jsonParser = bodyParser.json();
	var urlencParser = bodyParser.urlencoded({
		extended: true
	});
	var onHeaders = require('on-headers');
	var typer = require('media-typer');
	var isUtf8 = require('is-utf8');

	var parseString = require('xml2js').parseString;
	var js2xmlparser = require("js2xmlparser");


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

	function getSignature(token, timestamp, nonce, encrypt) {
		var shasum = crypto.createHash('sha1');
		var arr = [token, timestamp, nonce, encrypt].sort();
		shasum.update(arr.join(''));
		return shasum.digest('hex');
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

	function encrypt(text, encodingAESKey, decId) {
		var key = new Buffer(encodingAESKey + '=', 'base64');
		var iv = key.slice(0, 16);
		var randomString = crypto.pseudoRandomBytes(16);
		var msg = new Buffer(text);
		var msgLength = new Buffer(4);
		msgLength.writeUInt32BE(msg.length, 0);

		var id = new Buffer(decId);
		var bufMsg = Buffer.concat([randomString, msgLength, msg, id]);
		var encoded = PKCS7EncoderEncode(bufMsg);
		var cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
		cipher.setAutoPadding(false);
		var cipheredMsg = Buffer.concat([cipher.update(encoded), cipher.final()]);
		return cipheredMsg.toString('base64');
	};

	function object2wechatXml(wechatObj) {
		var result = {};
		for (var ele in wechatObj) {
			result[ele] = [wechatObj[ele]];
		}
		return result;
	}

	function wechatXml2object(wechatXml) {
		var result = {};
		for (var ele in wechatXml) {
			result[ele] = wechatXml[ele][0];
		}
		return result;
	}


	function rawBodyParser(req, res, next) {
		if (req._body) {
			return next();
		}
		req.body = "";
		req._body = true;

		var isText = true;
		var checkUTF = false;

		if (req.headers['content-type']) {
			var parsedType = typer.parse(req.headers['content-type'])
			if (parsedType.type === "text") {
				isText = true;
			} else if (parsedType.subtype === "xml" || parsedType.suffix === "xml") {
				isText = true;
			} else if (parsedType.type !== "application") {
				isText = false;
			} else if (parsedType.subtype !== "octet-stream") {
				checkUTF = true;
			}
		}

		getBody(req, {
			length: req.headers['content-length'],
			encoding: isText ? "utf8" : null
		}, function(err, buf) {
			if (err) {
				return next(err);
			}
			if (!isText && checkUTF && isUtf8(buf)) {
				buf = buf.toString()
			}

			req.body = buf;
			next();
		});
	}

	var corsSetup = false;

	function createRequestWrapper(node, req) {
		// This misses a bunch of properties (eg headers). Before we use this function
		// need to ensure it captures everything documented by Express and HTTP modules.
		var wrapper = {
			_req: req
		};
		var toWrap = [
			"param",
			"get",
			"is",
			"acceptsCharset",
			"acceptsLanguage",
			"app",
			"baseUrl",
			"body",
			"cookies",
			"fresh",
			"hostname",
			"ip",
			"ips",
			"originalUrl",
			"params",
			"path",
			"protocol",
			"query",
			"route",
			"secure",
			"signedCookies",
			"stale",
			"subdomains",
			"xhr",
			"socket" // TODO: tidy this up
		];
		toWrap.forEach(function(f) {
			if (typeof req[f] === "function") {
				wrapper[f] = function() {
					node.warn(RED._("httpin.errors.deprecated-call", {
						method: "msg.req." + f
					}));
					var result = req[f].apply(req, arguments);
					if (result === req) {
						return wrapper;
					} else {
						return result;
					}
				}
			} else {
				wrapper[f] = req[f];
			}
		});
		return wrapper;
	}

	function createResponseWrapper(node, res) {
		var wrapper = {
			_res: res
		};
		var toWrap = [
			"append",
			"attachment",
			"cookie",
			"clearCookie",
			"download",
			"end",
			"format",
			"get",
			"json",
			"jsonp",
			"links",
			"location",
			"redirect",
			"render",
			"send",
			"sendfile",
			"sendFile",
			"sendStatus",
			"set",
			"status",
			"type",
			"vary"
		];
		toWrap.forEach(function(f) {
			wrapper[f] = function() {
				node.warn(RED._("httpin.errors.deprecated-call", {
					method: "msg.res." + f
				}));
				var result = res[f].apply(res, arguments);
				if (result === res) {
					return wrapper;
				} else {
					return result;
				}
			}
		});
		return wrapper;
	}

	var corsHandler = function(req, res, next) {
		next();
	}

	if (RED.settings.httpNodeCors) {
		corsHandler = cors(RED.settings.httpNodeCors);
		RED.httpNode.options("*", corsHandler);
	}

	function wechatIn(config) {
		RED.nodes.createNode(this, config);
		if (RED.settings.httpNodeRoot !== false) {

			if (!config.path) {
				this.warn(RED._("httpin.errors.missing-path"));
				return;
			}
			this.url = config.path;
			//var wechatToken = config.token;
			var nodeInfo = {
				appId: config.appid,
				encodingMode: config.encoding,
				key: config.key,
				decrypted_msg: {},
				wechatToken: config.token
			}
			console.log('encodingMode: ' + nodeInfo.encodingMode);


			var encodingAESKey = config.key;

			this.swaggerDoc = config.swaggerDoc;
			var node = this;

			this.errorHandler = function(err, req, res, next) {
				node.warn(err);
				res.sendStatus(500);
			};

			this.callback = function(req, res) {
				var msgid = RED.util.generateId();
				res._msgid = msgid;
				node.method = req.method.toLowerCase();
				console.log(node.method);
				if (node.method.match(/(^post$|^delete$|^put$|^options$)/)) {
					parseString(req.body, function(err, wechatMsg) {
						if (nodeInfo.encodingMode == 1) {

							if (wechatMsg.xml.Encrypt) {
								var decrpted_msg = decrypt(wechatMsg.xml.Encrypt[0], nodeInfo.key);
								nodeInfo.decrpted_msg = decrpted_msg;
								console.log(decrpted_msg);
								parseString(decrpted_msg.message, function(err, result) {
									console.log(result);
									node.send({
										_msgid: msgid,
										nodeInfo: nodeInfo,
										req: req,
										res: createResponseWrapper(node, res),
										wechat: wechatXml2object(result.xml)
									});
								});
							} else {
								node.error('Only accept encoded message!');
							}

						} else {
							node.send({
								_msgid: msgid,
								req: req,
								nodeInfo: nodeInfo,
								res: createResponseWrapper(node, res),
								wechat: wechatXml2object(wechatMsg.xml)
							});
						}
					});

				} else if (node.method == "get") {
					var originMsg = req.query;
					var msg = {
						req: req,
						res: createResponseWrapper(node, res),
						payload: originMsg.echostr
					};
					if (checkSignature(originMsg.signature, nodeInfo.wechatToken, originMsg.timestamp, originMsg.nonce)) {
						var statusCode = 200;
					} else {
						var statusCode = 400;
					}

					if (typeof msg.payload == "object" && !Buffer.isBuffer(msg.payload)) {
						msg.res._res.status(statusCode).jsonp(msg.payload);
					} else {
						if (msg.res._res.get('content-length') == null) {
							var len;
							if (msg.payload == null) {
								len = 0;
							} else if (Buffer.isBuffer(msg.payload)) {
								len = msg.payload.length;
							} else if (typeof msg.payload == "number") {
								len = Buffer.byteLength("" + msg.payload);
							} else {
								len = Buffer.byteLength(msg.payload);
							}
							msg.res._res.set('content-length', len);
						}
						msg.res._res.status(statusCode).send(msg.payload);
					};
				} else {
					node.send({
						_msgid: msgid,
						req: req,
						res: createResponseWrapper(node, res)
					});
				}
			};

			var httpMiddleware = function(req, res, next) {
				next();
			}

			if (RED.settings.httpNodeMiddleware) {
				if (typeof RED.settings.httpNodeMiddleware === "function") {
					httpMiddleware = RED.settings.httpNodeMiddleware;
				}
			}

			var metricsHandler = function(req, res, next) {
				next();
			}

			if (this.metric()) {
				metricsHandler = function(req, res, next) {
					var startAt = process.hrtime();
					onHeaders(res, function() {
						if (res._msgid) {
							var diff = process.hrtime(startAt);
							var ms = diff[0] * 1e3 + diff[1] * 1e-6;
							var metricResponseTime = ms.toFixed(3);
							var metricContentLength = res._headers["content-length"];
							//assuming that _id has been set for res._metrics in HttpOut node!
							node.metric("response.time.millis", {
								_msgid: res._msgid
							}, metricResponseTime);
							node.metric("response.content-length.bytes", {
								_msgid: res._msgid
							}, metricContentLength);
						}
					});
					next();
				};
			}

			RED.httpNode.get(this.url, httpMiddleware, corsHandler, metricsHandler, this.callback, this.errorHandler);
			RED.httpNode.post(this.url, httpMiddleware, corsHandler, metricsHandler, jsonParser, urlencParser, rawBodyParser, this.callback, this.errorHandler);


			this.on("close", function() {
				var node = this;
				RED.httpNode._router.stack.forEach(function(route, i, routes) {
					if (route.route && route.route.path === node.url && route.route.methods[node.method]) {
						routes.splice(i, 1);
					}
				});
			});
		} else {
			this.warn(RED._("httpin.errors.not-created"));
		}
	}
	RED.nodes.registerType("wechat in", wechatIn);

	function wechatOut(config) {
		RED.nodes.createNode(this, config);
		var node = this;
		this.on("input", function(msg) {
			if (msg.res) {
				var statusCode = msg.statusCode || 200;
				var wechatData = {};
				if (msg.wechat) {
					var oriXML = object2wechatXml(msg.wechat);
					
					if(msg.payload){
						oriXML.MsgType = "text";
						oriXML.Content = msg.payload;
					}
					
					var _tmp = oriXML.ToUserName;
					oriXML.ToUserName = oriXML.FromUserName;
					oriXML.FromUserName = _tmp;

					if (msg.nodeInfo.encodingMode == 1) {
						var feed4encrypt = js2xmlparser("xml", oriXML);
						var encrypted_msg = encrypt(feed4encrypt, msg.nodeInfo.key, msg.nodeInfo.appId);
						var returnTimeStamp = new Date().getTime();
						var returnNonce = parseInt((Math.random() * 100000000000), 10);
						msg.xml = {
							MsgSignature: getSignature(msg.nodeInfo.wechatToken, returnTimeStamp, returnNonce, encrypted_msg),
							TimeStamp: returnTimeStamp,
							Nonce: returnNonce,
							Encrypt: encrypted_msg
						};
						msg.payload = js2xmlparser("xml", msg.xml);
						console.log(msg.payload);
					} else {
						msg.payload = js2xmlparser("xml", oriXML);

					}
				} else {
					node.error("missing wechat context");
				}
				if (typeof msg.payload == "object" && !Buffer.isBuffer(msg.payload)) {
					msg.res._res.status(statusCode).jsonp(msg.payload);
				} else {
					if (msg.res._res.get('content-length') == null) {
						var len;
						if (msg.payload == null) {
							len = 0;
						} else if (Buffer.isBuffer(msg.payload)) {
							len = msg.payload.length;
						} else if (typeof msg.payload == "number") {
							len = Buffer.byteLength("" + msg.payload);
						} else {
							len = Buffer.byteLength(msg.payload);
						}
						msg.res._res.set('content-length', len);
					}

					msg.res._res.status(statusCode).send(msg.payload);
				}
			} else {
				node.warn(RED._("httpin.errors.no-response"));
			}
		});
	}
	RED.nodes.registerType("wechat out", wechatOut);
}
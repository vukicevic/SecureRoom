function Key(material, created, name) {
	var hash   = Hash(),
		oracle = Asymmetric(Crunch(), hash),
		
		type        = (typeof name !== "undefined") ? 3 : 2,
		fingerprint = generateFingerprint(),
		signatures  = {},
		verified;		

	function makeBase() {
		return [4]
				.concat(ArrayUtil.fromWord(created))
				.concat([type])
				.concat(ArrayUtil.makeMpi(material.n))
				.concat(ArrayUtil.makeMpi(material.e));
	}

	function makeEphemeralSigBase() {
		return [4,24,2,2,0,15,5,2]
			.concat(ArrayUtil.fromWord(created))
			.concat([2,27,4,5,9])
			.concat(ArrayUtil.fromWord(86400));
	}

	function makeMasterSigBase() {
		return [4,19,3,2,0,26,5,2]
			.concat(ArrayUtil.fromWord(created))
			.concat([2,27,3,5,9])
			.concat(ArrayUtil.fromWord(86400))
			.concat([4,11,7,8,9,2,21,2,2,22,0]);
	}

	function generateFingerprint() {
		var base = makeBase();

		return ArrayUtil.toHex(hash.digest([153].concat(ArrayUtil.fromHalf(base.length)).concat(base)));
	}

	function generateSignatureHash(signer) {
		var keyHead, sigHead, suffix, 
			base = signer.base;

		if (typeof name !== "undefined") {
			keyHead = [180]
						.concat(ArrayUtil.fromWord(name.length))
						.concat(ArrayUtil.fromString(name));

			sigHead = makeMasterSigBase();
		} else {
			keyHead = makeBase();
			keyHead = [153].concat(ArrayUtil.fromHalf(keyHead.length)).concat(keyHead);

			sigHead = makeEphemeralSigBase();
		}

		suffix  = [4,255].concat(ArrayUtil.fromWord(sigHead.length));

		return hash.digest(
			[153].concat(ArrayUtil.fromHalf(base.length)).concat(base).concat(keyHead).concat(sigHead).concat(suffix)
		);
	}

	return {

		get base () {
			return makeBase();
		},

		get signatureBase () {
			return (type === 3) ? makeMasterSigBase() : makeEphemeralSigBase();
		},

		get created () {
			return created;
		},

		get fingerprint () {
			return fingerprint;
		},

		get id () {
			return fingerprint.substr(-16);
		},

		get json () {
			var json = {};
			
			json.created    = created;
			json.signatures = signatures;
			
			json.material   = {};
			json.material.e = material.e;
			json.material.n = material.n;

			if (typeof name !== "undefined")
				json.name = name;

			return json;
		},

		get material () {
			return material;
		},

		//TEMP WORKAROUNG
		get data () {
			return material;
		},
		//TEMP WORKAROUNG

		get name () {
			return name;
		},

		get signatures () {
			return signatures;
		},

		get size () {
			return ArrayUtil.bitLength(material.n);
		},

		get type () {
			return type;
		},

		set signatures (value) {
			signatures = value;
		},

		sign: function(signer) {
			if (signer.isPrivate() && signer.isMaster()) {
				var signatureHash = generateSignatureHash(signer),
					sigdata = {};

				sigdata.signature = oracle.sign(signer, signatureHash, true);
				sigdata.hashcheck = signatureHash.slice(0, 2);

				signatures[signer.id] = sigdata;

				verified = true;
			}
		},

		verify: function(signer) {
			if (typeof signatures[signer.id] !== "undefined") {
				if (verified !== false) {
					var signatureHash = generateSignatureHash(signer);
					verified = oracle.verify(signer, signatureHash, signatures[signer.id].signature, true);
				}

				return verified;
			}
		},

		isMaster: function() {
			return typeof name !== "undefined";
		},

		isPrivate: function() {
			return typeof material.d !== "undefined";
		}
	}
}

function User(master) {
	var emphemeral;

 	return {
		get name () {
			return master.name;
		},

		get master () {
			return master;
		},

		get ephemeral () {
			return ephemeral;
		},

		set ephemeral (key) {
			ephemeral = key;
		}
	}
}


function ExportUtil() {
	function makeLength(l) {
		return (l < 256) ? [l] : (l < 65536) ? ArrayUtil.fromHalf(l) : ArrayUtil.fromWord(l);
	}

	function makeTag(t, l) {
		return (l > 65535) ? [t*4 + 130] : (l > 255) ? [t*4 + 129] : [t*4 + 128];
	}

	function makeNamePacket(name) {
		var packet = ArrayUtil.fromString(name);
		
		return makeTag(13, packet.length).concat(makeLength(packet.length)).concat(packet);
	}

	function makePublicKeyPacket(key) {
		var len = 10 + key.material.n.length + key.material.e.length,
			tag = (key.type === 3) ? 6 : 14;

		return makeTag(tag, len).concat(makeLength(len)).concat(key.base);
	}

	function makeSecretKeyPacket(key) {
		var len = 21 + key.material.n.length + key.material.e.length + key.material.d.length + key.material.p.length + key.material.q.length + key.material.u.length,
			tag = (key.type === 3) ? 5 : 7,
			tmp = [0].concat(ArrayUtil.makeMpi(key.material.d))
					 .concat(ArrayUtil.makeMpi(key.material.p))
					 .concat(ArrayUtil.makeMpi(key.material.q))
					 .concat(ArrayUtil.makeMpi(key.material.u));

		return makeTag(tag, len).concat(makeLength(len)).concat(key.base).concat(tmp).concat(ArrayUtil.fromHalf(tmp.reduce(function(a, b) { return a + b }) % 65536));
	}

	function makeSignaturePacket(key) {
		var head = key.signatureBase,
			list = [],
			pack, id;
			
		for (id in key.signatures) {
			pack = head.concat([0, 10, 9, 16])
					.concat(ArrayUtil.fromHex(key.id))
					.concat(key.signatures[id].hashcheck)
					.concat(ArrayUtil.makeMpi(key.signatures[id].signature));
		
			list = list.concat(makeTag(2, pack.length)).concat(makeLength(pack.length)).concat(pack);
		}

		return list;
	}

	return {
		publicGpg: function(user) {
			var p = makePublicKeyPacket(user.master)
					.concat(makeNamePacket(user.name))
					.concat(makeSignaturePacket(user.master))
					.concat(makePublicKeyPacket(user.ephemeral))
					.concat(makeSignaturePacket(user.ephemeral));

			return ArmorUtil.dress({"type": "PUBLIC KEY BLOCK", "headers": {"Version": "SecureRoom"}, "packets": p});
		},

		privateGpg: function(user) {
			var p = makeSecretKeyPacket(user.master)
					.concat(makeNamePacket(user.name))
					.concat(makeSignaturePacket(user.master))
					.concat(makeSecretKeyPacket(user.ephemeral))
					.concat(makeSignaturePacket(user.ephemeral));

			return ArmorUtil.dress({"type": "PRIVATE KEY BLOCK", "headers": {"Version": "SecureRoom"}, "packets": p});
		}
	}
}
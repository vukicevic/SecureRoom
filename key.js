function Key(material, created, name) {
	var hash   = Hash(),
		oracle = Asymmetric(Crunch(), hash),
		
		type        = (typeof name !== "undefined") ? 3 : 2,
		fingerprint = generateFingerprint(),
		signatures  = {},
		verified;		

	function makeMpi(a) {
    	return ArrayUtil.fromHalf(ArrayUtil.bitLength(a)).concat(a);
  	}

	function makeLength(l) {
		return (l < 256) ? [l] : (l < 65536) ? ArrayUtil.fromHalf(l) : ArrayUtil.fromWord(l);
	}

	function makeTag(t, l) {
		return (l > 65535) ? [t*4 + 130] : (l > 255) ? [t*4 + 129] : [t*4 + 128];
	}

	function makeBase(c, t, m) {
		return [4]
				.concat(ArrayUtil.fromWord(c))
				.concat([t])
				.concat(makeMpi(m.n))
				.concat(makeMpi(m.e));
	}

	function generateFingerprint() {
		var base = makeBase(created, type, material);

		return ArrayUtil.toHex(hash.digest([153].concat(ArrayUtil.fromHalf(base.length)).concat(base)));
	}

	function generateSignatureHash(signer) {
		var keyHead, sigHead, suffix, 
			base = makeBase(signer.created, signer.type, signer.material);

		if (typeof name !== "undefined") {
			keyHead = [180]
						.concat(ArrayUtil.fromWord(name.length))
						.concat(ArrayUtil.fromString(name));

			sigHead = makeMasterSigHead();
		} else {
			keyHead = makeBase(created, type, material);
			keyHead = [153].concat(ArrayUtil.fromHalf(keyHead.length)).concat(keyHead);

			sigHead = makeEphemeralSigHead();
		}

		suffix  = [4,255].concat(ArrayUtil.fromWord(sigHead.length));

		return hash.digest(
			[153].concat(ArrayUtil.fromHalf(base.length)).concat(base).concat(keyHead).concat(sigHead).concat(suffix)
		);
	}
	
	function makeEphemeralSigHead() {
		return [4,24,2,2,0,15,5,2]
			.concat(ArrayUtil.fromWord(created))
			.concat([2,27,4,5,9])
			.concat(ArrayUtil.fromWord(86400));
	}

	function makeMasterSigHead() {
		return [4,19,3,2,0,26,5,2]
			.concat(ArrayUtil.fromWord(created))
			.concat([2,27,3,5,9])
			.concat(ArrayUtil.fromWord(86400))
			.concat([4,11,7,8,9,2,21,2,2,22,0]);
	}

	/* PACKET EXPORT FUNCTIONS */
	function makeSignaturePackets() {
		var head = (typeof name !== "undefined") ? makeMasterSigHead() : makeEphemeralSigHead(),
			list = [],
			pack, id;
			
		for (id in signatures) {
			pack = head.concat([0, 10, 9, 16])
					.concat(ArrayUtil.fromHex(id))
					.concat(signatures[id].hashcheck)
					.concat(makeMpi(signatures[id].signature));
		
			list = list.concat(makeTag(2, pack.length)).concat(makeLength(pack.length)).concat(pack);
		}

		return list;
	}
	
	function makePublicKeyPacket() {
		var len = 10 + material.n.length + material.e.length,
			tag = (typeof name !== "undefined") ? 6 : 14;

		return makeTag(tag, len).concat(makeLength(len)).concat(makeBase(created, type, material));
	}

	function makeSecretKeyPacket() {
		var len = 21 + material.n.length + material.e.length + material.d.length + material.p.length + material.q.length + material.u.length,
			tag = (typeof name !== "undefined") ? 5 : 7,
			tmp = [0].concat(makeMpi(material.d))
					.concat(makeMpi(material.p))
					.concat(makeMpi(material.q))
					.concat(makeMpi(material.u));

		return makeTag(tag, len).concat(makeLength(len)).concat(makeBase(created, type, material)).concat(tmp).concat(ArrayUtil.fromHalf(tmp.reduce(function(a, b) { return a + b }) % 65536));
	}

	function makeNamePacket() {
		var packet = ArrayUtil.fromString(name);
		
		return makeTag(13, packet.length).concat(makeLength(packet.length)).concat(packet);
	}
	/* PACKET EXPORT FUNCTIONS */

	return {
		/* PACKET EXPORT GETTERS */
		get namePacket () {
			return makeNamePacket();
		},

		get signaturePackets () {
			return makeSignaturePackets();
		},

		get publicPacket () {
			return makePublicKeyPacket();
		},

		get secretPacket() {
			return makeSecretKeyPacket();
		},
		/* PACKET EXPORT GETTERS */

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

		get size () {
			return ArrayUtil.bitLength(material.n);
		},

		get type () {
			return type;
		},

		set signatures (value) {
			signatures = value;
		},

		sign: function(key) {
			if (key.isPrivate() && key.isMaster()) {
				var signatureHash = generateSignatureHash(key),
					sigdata = {};

				sigdata.signature = oracle.sign(key, signatureHash, true);
				sigdata.hashcheck = signatureHash.slice(0, 2);

				signatures[key.id] = sigdata;

				verified = true;
			}
		},

		verify: function(key) {
			if (typeof signatures[key.id] !== "undefined") {
				if (verified !== false) {
					var signatureHash = generateSignatureHash(key);
					verified = oracle.verify(key, signatureHash, signatures[key.id].signature, true);
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

var ExportUtil = {
	publicGpgPacket: function(master, ephemeral) {
		var packets = master.publicPacket
						.concat(master.namePacket)
						.concat(master.signaturePackets)
						.concat(ephemeral.publicPacket)
						.concat(ephemeral.signaturePackets);

		return ArmorUtil.dress({"type": "PUBLIC KEY BLOCK", "headers": {"Version": "SecureRoom"}, "packets": packets});
	}
}

/*function User(master) {
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
}*/

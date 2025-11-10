package artificialrobotics.com.SigningAuthorisation.examples;

import artificialrobotics.com.SigningAuthorisation.json.JsonCanonicalizerJcs;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Example: Verification of a detached JWS in Berlin Group wrapper using PS512
 * with a strict "pre-hash" model (separating hashing and verification).
 *
 * Flow: 1) Parse Berlin Group wrapper, extract Base64URL "protected" and
 * "signature". 2) Canonicalize payload with JCS (RFC 8785) and Base64URL-encode
 * it. 3) Build JWS signing input: ASCII(protectedB64 + "." + payloadB64) (RFC
 * 7515 §5). 4) Compute SHA-512(signingInput) (RFC 7518 PS512). 5) Verify with
 * JCA/JCE "RAWRSASSA-PSS" (BC provider), params: SHA-512 / MGF1(SHA-512) /
 * saltLen=64 / trailer=0xBC (RFC 8017).
 *
 * Specs referenced: - RFC 7515 (JWS) : signing input, Base64URL - RFC 7518
 * (JWA) : PS512 definition - RFC 8785 (JCS) : JSON canonicalization - RFC 8017
 * (PKCS#1): RSASSA-PSS - JCA/JCE : provider + Signature API - ETSI TS 119 182 :
 * JAdES context for protected claims (informative)
 */
public class ExampleVerifyBerlinGroupRawPss {

	/** Register BC provider for "RAWRSASSA-PSS". */
	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	/* ---------- Public API ---------- */

	/**
	 * Verify a Berlin Group wrapped, detached PS512 signature using a PEM public
	 * key or certificate.
	 *
	 * @param berlinGroupJson JSON: { "signatureData":{ "protected": "...",
	 *                        "signature":"..." } }
	 * @param payloadJson     Detached payload (business JSON); will be
	 *                        canonicalized via JCS (RFC 8785)
	 * @param pemPubOrCert    PEM string: "-----BEGIN PUBLIC KEY-----" (X.509 SPKI)
	 *                        or "-----BEGIN CERTIFICATE-----" (Optionally:
	 *                        "-----BEGIN RSA PUBLIC KEY-----" (PKCS#1) will be
	 *                        wrapped into SPKI)
	 * @return true if signature verifies; false otherwise
	 * @throws Exception on parsing errors or unsupported formats
	 */
	public static boolean verifyDetachedBerlinGroup(String berlinGroupJson, String payloadJson, String pemPubOrCert)
			throws Exception {

		// 1) Extract protected and signature from BG JSON (minimal JSON scanning to
		// keep example dependency-free)
		BG bg = parseBerlinGroupWrapper(berlinGroupJson);

		// 2) Canonicalize payload using JCS and then Base64URL-encode it (mirrors
		// signer)
		String payloadB64 = payloadJsonToBase64UrlJcs(payloadJson);

		// 3) Build signing input (ASCII) as defined by RFC 7515 §5
		byte[] signingInput = (bg.protectedB64 + "." + payloadB64).getBytes(StandardCharsets.US_ASCII);

		// 4) Compute SHA-512 over signing input (PS512 requirement in RFC 7518)
		byte[] digest = MessageDigest.getInstance("SHA-512").digest(signingInput);

		// 5) Verify pre-hash with RAWRSASSA-PSS (SHA-512 / MGF1(SHA-512) / saltLen=64 /
		// trailer=0xBC)
		byte[] sig = Base64.getUrlDecoder().decode(bg.signatureB64);
		PublicKey pub = parsePublicKeyFromPemOrCert(pemPubOrCert);
		return verifyPreHashedPS512(pub, digest, sig);
	}

	/* ---------- Steps mirroring the signing side ---------- */

	/**
	 * Canonicalize JSON payload via JCS (RFC 8785) and return Base64URL of UTF-8
	 * bytes.
	 */
	public static String payloadJsonToBase64UrlJcs(String jsonPayloadPrettyOrCompact) {
		String canonical = JsonCanonicalizerJcs.canonicalize(jsonPayloadPrettyOrCompact);
		byte[] utf8 = canonical.getBytes(StandardCharsets.UTF_8);
		return Base64.getUrlEncoder().withoutPadding().encodeToString(utf8);
	}

	/**
	 * Verify ONLY the precomputed SHA-512 digest using RSASSA-PSS with PS512
	 * parameters. Uses JCA/JCE Signature with the Bouncy Castle provider and
	 * "RAWRSASSA-PSS".
	 *
	 * @param pub          RSA public key
	 * @param sha512Digest Precomputed SHA-512(signingInput)
	 * @param signature    Signature bytes (JWS uses raw PSS bytes; already
	 *                     Base64URL-decoded)
	 * @return true if valid, false otherwise
	 */
	public static boolean verifyPreHashedPS512(PublicKey pub, byte[] sha512Digest, byte[] signature) throws Exception {
		var s = java.security.Signature.getInstance("RAWRSASSA-PSS", "BC");
		var pss = new java.security.spec.PSSParameterSpec("SHA-512", "MGF1",
				new java.security.spec.MGF1ParameterSpec("SHA-512"), 64, 1);
		s.setParameter(pss);
		s.initVerify(pub);
		s.update(sha512Digest);
		return s.verify(signature);
	}

	/* ---------- Minimal JSON parsing for the Berlin Group wrapper ---------- */

	/** Holder for extracted BG fields. */
	public static final class BG {
		public final String protectedB64;
		public final String signatureB64;

		public BG(String p, String s) {
			this.protectedB64 = p;
			this.signatureB64 = s;
		}
	}

	/**
	 * Parse: { "signatureData": { "protected":"...", "signature":"..." } } Minimal,
	 * robust-enough extraction without external JSON libs.
	 */
	public static BG parseBerlinGroupWrapper(String json) {
		String obj = json.replaceAll("[\\r\\n]", "").trim();
		// Very small scan for the two fields (assumes simple JSON with quoted values)
		String prot = extractJsonString(obj, "\"protected\"");
		String sig = extractJsonString(obj, "\"signature\"");
		if (prot == null || sig == null) {
			throw new IllegalArgumentException("Missing 'protected' or 'signature' in Berlin Group JSON.");
		}
		return new BG(prot, sig);
	}

	/**
	 * Extract a JSON string value for a key like "\"protected\"" → value without
	 * quotes.
	 */
	private static String extractJsonString(String json, String keyWithQuotes) {
		int i = json.indexOf(keyWithQuotes);
		if (i < 0)
			return null;
		int colon = json.indexOf(':', i);
		if (colon < 0)
			return null;
		int q1 = json.indexOf('"', colon + 1);
		if (q1 < 0)
			return null;
		int q2 = json.indexOf('"', q1 + 1);
		if (q2 < 0)
			return null;
		return json.substring(q1 + 1, q2);
	}

	/* ---------- PEM public key / certificate parsing ---------- */

	/**
	 * Parse a PEM public key or certificate into a JCA PublicKey. Supports: -
	 * "BEGIN PUBLIC KEY" → X.509 SubjectPublicKeyInfo (SPKI) - "BEGIN CERTIFICATE"
	 * → X.509 certificate (extracts SPKI) - "BEGIN RSA PUBLIC KEY" → PKCS#1
	 * RSAPublicKey (wrapped into SPKI)
	 */
	public static PublicKey parsePublicKeyFromPemOrCert(String pem) throws Exception {
		PemObject po = readPem(pem);
		String type = po.getType();
		byte[] content = po.getContent();
		KeyFactory kf = KeyFactory.getInstance("RSA");

		switch (type) {
		case "PUBLIC KEY": {
			// X.509 SPKI directly
			return kf.generatePublic(new X509EncodedKeySpec(content));
		}
		case "CERTIFICATE": {
			// Extract SPKI from certificate
			java.security.cert.Certificate cert = java.security.cert.CertificateFactory.getInstance("X.509")
					.generateCertificate(new java.io.ByteArrayInputStream(content));
			return cert.getPublicKey();
		}
		case "RSA PUBLIC KEY": {
			// PKCS#1 RSAPublicKey → wrap into X.509 SubjectPublicKeyInfo
			byte[] spki = wrapPkcs1RsaPublicKeyToSpki(content);
			return kf.generatePublic(new X509EncodedKeySpec(spki));
		}
		default:
			throw new IllegalArgumentException("Unsupported PEM type: " + type);
		}
	}

	/** Read a single PEM object from string. */
	private static PemObject readPem(String pem) throws IOException {
		try (Reader r = new StringReader(pem); PemReader pr = new PemReader(r)) {
			PemObject po = pr.readPemObject();
			if (po == null)
				throw new IllegalArgumentException("No PEM object found");
			return po;
		}
	}

	/*
	 * ---------- Tiny ASN.1 helpers (PKCS#1 RSAPublicKey → X.509 SPKI) ----------
	 */

	/**
	 * Wrap a PKCS#1 RSAPublicKey into an X.509 SubjectPublicKeyInfo:
	 *
	 * SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier {
	 * rsaEncryption, NULL }, subjectPublicKey BIT STRING (RSAPublicKey) }
	 *
	 * AlgorithmIdentifier for rsaEncryption: SEQ { OID 1.2.840.113549.1.1.1, NULL }
	 * We encode the AlgorithmIdentifier as a readable HEX string.
	 */
	private static byte[] wrapPkcs1RsaPublicKeyToSpki(byte[] pkcs1RsaPublicDer) {
		// DER for AlgorithmIdentifier: SEQ(OID 1.2.840.113549.1.1.1, NULL)
		String algIdHex = "300D06092A864886F70D0101010500";
		byte[] algId = hexToBytes(algIdHex);

		// subjectPublicKey is a BIT STRING containing the RSAPublicKey DER bytes (with
		// 0 unused bits)
		byte[] bitString = derBitString(pkcs1RsaPublicDer);

		// SPKI = SEQUENCE { algId, bitString }
		byte[] body = concat(algId, bitString);
		return derSequence(body);
	}

	/** Build a DER BIT STRING with 0 unused bits around the provided bytes. */
	private static byte[] derBitString(byte[] val) {
		byte[] len = derLen(1 + val.length); // 1 byte for "unused bits" count
		byte[] out = new byte[1 + len.length + 1 + val.length];
		out[0] = 0x03; // BIT STRING tag
		System.arraycopy(len, 0, out, 1, len.length);
		out[1 + len.length] = 0x00; // number of unused bits = 0
		System.arraycopy(val, 0, out, 1 + len.length + 1, val.length);
		return out;
	}

	/** Build a DER SEQUENCE for the provided body. */
	private static byte[] derSequence(byte[] body) {
		byte[] len = derLen(body.length);
		byte[] out = new byte[1 + len.length + body.length];
		out[0] = 0x30;
		System.arraycopy(len, 0, out, 1, len.length);
		System.arraycopy(body, 0, out, 1 + len.length, body.length);
		return out;
	}

	/** Encode a DER length (short/long form). */
	private static byte[] derLen(int length) {
		if (length < 128)
			return new byte[] { (byte) length };
		int tmp = length, bytes = 0;
		while (tmp > 0) {
			bytes++;
			tmp >>= 8;
		}
		byte[] out = new byte[1 + bytes];
		out[0] = (byte) (0x80 | bytes);
		for (int i = bytes; i > 0; i--) {
			out[i] = (byte) (length & 0xFF);
			length >>= 8;
		}
		return out;
	}

	/** Concatenate multiple byte arrays. */
	private static byte[] concat(byte[]... arrs) {
		int n = 0, off = 0;
		for (byte[] a : arrs)
			n += a.length;
		byte[] out = new byte[n];
		for (byte[] a : arrs) {
			System.arraycopy(a, 0, out, off, a.length);
			off += a.length;
		}
		return out;
	}

	/** Convert a hex string (spaces allowed) to byte[]. */
	private static byte[] hexToBytes(String hex) {
		String h = hex.replaceAll("\\s+", "");
		if ((h.length() & 1) != 0)
			throw new IllegalArgumentException("Odd-length hex: " + hex);
		byte[] out = new byte[h.length() / 2];
		for (int i = 0; i < out.length; i++) {
			int hi = Character.digit(h.charAt(2 * i), 16);
			int lo = Character.digit(h.charAt(2 * i + 1), 16);
			if (hi < 0 || lo < 0)
				throw new IllegalArgumentException("Invalid hex at pos " + (2 * i));
			out[i] = (byte) ((hi << 4) | lo);
		}
		return out;
	}

	/* ---------- Demo ---------- */

	/**
	 * Minimal demo: verifies a Berlin Group wrapper against a payload and a PEM
	 * public key/certificate. Note: RSASSA-PSS is randomized (salt), so to see
	 * "true" you must feed a wrapper that matches the inputs.
	 */
	public static void main(String[] args) throws Exception {
		// Example inputs (placeholders; replace with actual values from your signing
		// run)
		String berlinGroupWrapper = """
				{
				  "signatureData": {
				    "protected": "eyJhbGciOiJQUzUxMiIsInNpZ1QiOiIyMDI1LTExLTA5VDE5OjI3OjQyWiIsInN1YiI6Im15UGF5bWVudFJlc291cmNlSWQxMjM0NSIsImV0c2lDYW5vbmljYWxpemF0aW9uIjoiaHR0cDovL2pzb24tY2Fub25pY2FsaXphdGlvbi5vcmcvYWxnb3JpdGhtIiwieDV1IjoiaHR0cHM6Ly9leGFtcGxlLm9yZy9jZXJ0cy9tZWluZV90ZXN0X2dtYmhfY2VydC5wZW0iLCJjcml0IjpbImV0c2lDYW5vbmljYWxpemF0aW9uIiwic2lnVCIsInN1YiJdfQ",
				    "signature": "hzj7-nv8MTt2lItCrXjWtH4kgTVCONtV4mXJay7Fpg-YGEM9OnwDRgHNv-eXiY0I4wpnQajlrgkDTHhBXHoXJjTnUA0xShxCap3P0K2z_7eNqBUuAiR3fvyyESK_j57kpzJsEmVZjeEjtPJYcM_K4n-E56K0xqdsv_gTtkd4c2Az0P1hdG9-RV1tlA4QQADWrhrkTPAYBmsAjgoldtcCwdjw1P9Ll-nqIq4cl38-bobZZaCi13MgrE2XiCUQzn3RUMxaB-JLV7vZnm-tQ_CdAB_DF1_Gu2VUq2Okmb2SvOV9DCdfczdfRKewYrBMUrwmZ6K4Q508O7tQKTAyXIks5bt1wLxSMk036mSqtnIYHbZVefXqJgMqMr45yNIHusjxjvnZRBH_f0LYQzQ77NDhChP0zS8559c7qjHcgHfx5uB_KL9BoCIiY0uIl68uMI1pnGrzAZe8gnQ1uNRL8sE1aA5txmc_Fq3V7BU7JHibYEckU9O9968THuaXIyP14hUe"
				  }
				}
				        """;

		String payloadJson = """
				        {
				          "amount": "10.50",
				          "currency": "EUR",
				          "debtor": {"iban":"DE02120300000000202051"},
				          "creditor": {"iban":"DE75512108001245126199"},
				          "remittanceInformation": "BG-Sample"
				        }
				""";

		// Either SPKI public key or certificate
		String pemPubOrCert = """
				-----BEGIN CERTIFICATE-----
				MIIEtTCCAx2gAwIBAgIUHDxubp1z8bX3UbVVOe/XskJvCqMwDQYJKoZIhvcNAQEN
				BQAwbTEnMCUGA1UEAwweTWVpbmUgVGVzdCBHbWJIIC0gZVNlYWwgKFRlc3QpMRgw
				FgYDVQQKDA9NZWluZSBUZXN0IEdtYkgxCzAJBgNVBAYTAkRFMRswGQYDVQQFExJO
				VFItREUtSEJSLVRFU1QxMjMwHhcNMjUxMDI3MTUwNzMyWhcNMzUxMDI2MTUwNzMy
				WjBtMScwJQYDVQQDDB5NZWluZSBUZXN0IEdtYkggLSBlU2VhbCAoVGVzdCkxGDAW
				BgNVBAoMD01laW5lIFRlc3QgR21iSDELMAkGA1UEBhMCREUxGzAZBgNVBAUTEk5U
				Ui1ERS1IQlItVEVTVDEyMzCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGB
				AK9ICapcC/kIXyuhwt5UK+NyXYx0ARjFiSj0Jw3CoxlGUDtRE/ax/Xu5OHtQjCmX
				a1EWLF+mOP8ba/tGAMAoXnq6XhHq363sXHNVTfhs9zZ1oPBwDIWBW/KmPUaDdmKg
				8Fxba2ARRpO8ZONvwzO34i+JKtJhnvgynrCL6/Ptscz8eAixrOwznl+AATA4/kbp
				Nhxb/gjwN+fd34Ep/eGo9MNYua1tcMaLEBjrwXT9TjmFDaiMqsemcfldeDUtDPlA
				5z5eafqyQd3dHzX8Qc3rAjQV2HYfgJ+VX4Bt1fRAyRp2vdIpNPlFAngMTj0vmlSZ
				eHsN+l6jjLWg8CcbTeFmWzkeAJynFWEFz8VvC+jdVzBJ6NBRxVegbAy96u6nPfMA
				jTk3AAhDfurY5cTuvHNThozto/nkl1cqrKPS39+1uQBytMpvzBaaCbga4XIizreQ
				SI3BoAZkFzZaSEK+Y0FEYvN2EqcpsrssfC+jBX12kuNH4fvULUTln3NAylOAnP0a
				4QIDAQABo00wSzAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIGwDAdBgNVHREE
				FjAUghJ0ZXN0LmV4YW1wbGUubG9jYWwwDAYGBACORgEBBAIwADANBgkqhkiG9w0B
				AQ0FAAOCAYEAco5WAJpyWNt97EQdsjA87zgRIAmVzB3HMou+putUwqrL6GDAaJhg
				W5c4DlBoOqJOkCOufiPons1C720GoEX3rxOTdvpq95AgucerQX+J7qFUA4HCvoKJ
				wSgXy7fzs2rDXxTTeKyeBVh/IJE0DwPr/5OIaGPchRUXUXFki5BAgdk14x4r37Xl
				Kyeto2U3ikVpfX6fjTrQYugxtrfzPsq5DmFtxb4lMTXXTUnG7hEiJ6oMeajsX/Mi
				RpwgeB23ydWej1gFwmifAt1rSUAsGBe6DIcCuTDKdjoW5DmLyzrrB5lhw+15L6xc
				GhjXSV+uw+Rv1joZ/RWTm/poUjEa0kGJb0h78LJO8utk9GCJMGg7/EFAQx21PFea
				90Gyd+ABIPUB6oK7e8p14YxarqmrOidg0Pz3KsEY+iJWppyj4zM0qBLfGUIQIKsF
				3UF7NlX2ShyLsTB5Y+nB2QpSmh1SC6X7sMafdHuTfAWrHxSKffPCXTlFaJiFr6NM
				IQbAuB6eFqeO
				-----END CERTIFICATE-----
				        """;

		boolean ok = verifyDetachedBerlinGroup(berlinGroupWrapper, payloadJson, pemPubOrCert);
		System.out.println("VALID (crypto-only, PS512, pre-hash): " + ok);
	}
}

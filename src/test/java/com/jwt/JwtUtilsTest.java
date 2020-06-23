package com.jwt;

import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import com.jwt.JwtSample.JwtUtils;
import com.jwt.JwtSample.KeyContract;

import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.junit4.SpringRunner;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;

@RunWith(SpringRunner.class)
public class JwtUtilsTest {

	@Test
	public void generateAndValidateTokenTest1() {
		try {
			final Map<String, Object> header = loadJwtHeader();
			final JSONObject jsonPayload = loadJwtPayload();
			Map<String, Object> keyPair = loadTestKeys();

			final String jwt = JwtUtils.createJWT(header, jsonPayload.toString(), keyPair);
			assertNotNull(jwt);
			assertNotEquals("", jwt);

			Jws<Claims> jws = JwtUtils.isTokenValid(jwt, keyPair);

			assertNotNull(jws);
			assertNotNull(jws.getHeader());
			assertNotNull(jws.getBody());

		} catch (InvalidKeySpecException | IOException | URISyntaxException | JSONException
				| NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}

	private JSONObject loadJwtPayload() throws JSONException {
		final JSONObject jsonPayload = new JSONObject();
		jsonPayload.put("name", "Alice");
		jsonPayload.put("age", "24");
		jsonPayload.put("cpf", "9999999999");
		return jsonPayload;
	}

	private Map<String, Object> loadJwtHeader() {
		final Map<String, Object> header = new HashMap<>();
		header.put("alg", "RS256");
		header.put("typ", "JWT");
		header.put("partner", "0341");
		header.put("version", "1");
		return header;
	}

	@Test
	public void validateTokenTest() {
		try {
			String jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.POstGetfAytaZS82wHcjoTyoqhMyxXiWdR7Nn7A29DNSl0EiXLdwJ6xC6AfgZWF1bOsS_TuYI3OG85AmiExREkrS6tDfTQ2B3WXlrr-wp5AokiRbz3_oB4OxG-W9KcEEbDRcZc0nH3L7LzYptiy1PtAylQGxHTWZXtGz4ht0bAecBgmpdgXMguEIcoqPJ1n3pIWk_dUZegpqx0Lka21H6XxUTxiy8OcaarA8zdnPUnV6AmNP3ecFawIFYdvJB_cm-GvpCSbr8G8y_Mllj8f4x9nBH8pQux89_6gUY618iYv7tuPWBFfEbLxtF2pZS6YC1aSfLQxeNe8djT9YjpvRZA";
			String publicKeyContent = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9MwIDAQAB";

			final KeyFactory kf = KeyFactory.getInstance("RSA");
			final X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyContent));
			final RSAPublicKey pubKey = (RSAPublicKey) kf.generatePublic(keySpecX509);

			final Map<String, Object> keyMap = new HashMap<>();
			keyMap.put(KeyContract.PUBLIC_KEY, pubKey);

			Jws<Claims> jws = JwtUtils.isTokenValid(jwt, keyMap);
			assertNotNull(jws);

		} catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}

	@Test
	public void invalidTokenTest() {
		try {
			String jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzrWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.POstGetfAytaZS82wHcjoTyoqhMyxXiWdR7Nn7A29DNSl0EiXLdwJ6xC6AfgZWF1bOsS_TuYI3OG85AmiExREkrS6tDfTQ2B3WXlrr-wp5AokiRbz3_oB4OxG-W9KcEEbDRcZc0nH3L7LzYptiy1PtAylQGxHTWZXtGz4ht0bAecBgmpdgXMguEIcoqPJ1n3pIWk_dUZegpqx0Lka21H6XxUTxiy8OcaarA8zdnPUnV6AmNP3ecFawIFYdvJB_cm-GvpCSbr8G8y_Mllj8f4x9nBH8pQux89_6gUY618iYv7tuPWBFfEbLxtF2pZS6YC1aSfLQxeNe8djT9YjpvRZA";
			String publicKeyContent = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9MwIDAQAB";

			final KeyFactory kf = KeyFactory.getInstance("RSA");
			final X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyContent));
			final RSAPublicKey pubKey = (RSAPublicKey) kf.generatePublic(keySpecX509);

			final Map<String, Object> keyMap = new HashMap<>();
			keyMap.put(KeyContract.PUBLIC_KEY, pubKey);

			Jws<Claims> jws = JwtUtils.isTokenValid(jwt, keyMap);
			assertNull(jws);

		} catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}

	@Test
	public void invalidTokenTest2() {
		try {
			String jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.POstGetfAytaZS82wHcjoTyoqhMyxXiWdR7Nn7A29DNSl0EiXWdwJ6xC6AfgZWF1bOsS_TuYI3OG85AmiExREkrS6tDfTQ2B3WXlrr-wp5AokiRbz3_oB4OxG-W9KcEEbDRcZc0nH3L7LzYptiy1PtAylQGxHTWZXtGz4ht0bAecBgmpdgXMguEIcoqPJ1n3pIWk_dUZegpqx0Lka21H6XxUTxiy8OcaarA8zdnPUnV6AmNP3ecFawIFYdvJB_cm-GvpCSbr8G8y_Mllj8f4x9nBH8pQux89_6gUY618iYv7tuPWBFfEbLxtF2pZS6YC1aSfLQxeNe8djT9YjpvRZA";
			String publicKeyContent = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9MwIDAQAB";

			final KeyFactory kf = KeyFactory.getInstance("RSA");
			final X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyContent));
			final RSAPublicKey pubKey = (RSAPublicKey) kf.generatePublic(keySpecX509);

			final Map<String, Object> keyMap = new HashMap<>();
			keyMap.put(KeyContract.PUBLIC_KEY, pubKey);

			Jws<Claims> jws = JwtUtils.isTokenValid(jwt, keyMap);
			assertNull(jws);

		} catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}

	private static Map<String, Object> loadTestKeys()
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, URISyntaxException {

		String privateKeyContent = new String(
				Files.readAllBytes(Paths.get(ClassLoader.getSystemResource("private_key_pkcs8.pem").toURI())));
		String publicKeyContent = new String(
				Files.readAllBytes(Paths.get(ClassLoader.getSystemResource("public_key.pem").toURI())));

		privateKeyContent = privateKeyContent.replaceAll("\\n", "").replace("-----BEGIN PRIVATE KEY-----", "")
				.replace("-----END PRIVATE KEY-----", "");
		publicKeyContent = publicKeyContent.replaceAll("\\n", "").replace("-----BEGIN PUBLIC KEY-----", "")
				.replace("-----END PUBLIC KEY-----", "");

		final KeyFactory kf = KeyFactory.getInstance("RSA");

		final PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyContent));
		final PrivateKey privateKey = kf.generatePrivate(keySpecPKCS8);

		final X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyContent));
		final RSAPublicKey pubKey = (RSAPublicKey) kf.generatePublic(keySpecX509);

		final Map<String, Object> keyMap = new HashMap<>();
		keyMap.put(KeyContract.PUBLIC_KEY, pubKey);
		keyMap.put(KeyContract.PRIVATE_KEY, privateKey);

		return keyMap;
	}

	@Test
	public void loadTestKeysTest() {
		Map<String, Object> keys = null;
		try {
			keys = loadTestKeys();
		} catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException | URISyntaxException e) {
			e.printStackTrace();
		}
		assertNotNull(keys);
		assertNotNull(keys.get(KeyContract.PRIVATE_KEY));
		assertNotNull(keys.get(KeyContract.PUBLIC_KEY));
	}

}

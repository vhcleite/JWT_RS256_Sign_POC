package com.jwt.JwtSample;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Map;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class JwtUtils {

	public static String createJWT(final Map<String, Object> header, final String payload, 
			final Map<String, Object> keyPair) {
		final JwtBuilder builder = Jwts.builder()//
				.setHeader(header)//
				.setPayload(payload)//
				.signWith(SignatureAlgorithm.RS256, (PrivateKey)keyPair.get(KeyContract.PRIVATE_KEY));
		return builder.compact();
	}

	public static Jws<Claims> isTokenValid(String token, Map<String, Object> keyPair) {
		Jws<Claims> jws = null;
		try {
			 jws = Jwts.parser().setSigningKey((PublicKey)keyPair.get(KeyContract.PUBLIC_KEY)).parseClaimsJws(token);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return jws;
	}

}

package com.manning.apisecurityinaction;

import java.io.FileInputStream;
import java.net.URI;
import java.net.http.*;
import java.security.KeyStore;
import java.security.interfaces.ECPrivateKey;
import java.util.*;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jwt.*;

import static java.time.Instant.now;
import static java.time.temporal.ChronoUnit.SECONDS;
import static spark.Spark.*;

public class JwtBearerClient {
    public static void main(String... args) throws Exception {
        var password = "changeit".toCharArray();
        var keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(new FileInputStream("keystore.p12"), password);
        var privateKey = (ECPrivateKey) keyStore.getKey("es256-key", password);

        var jwkSet = JWKSet.load(keyStore, alias -> password).toPublicJWKSet();

        secure("localhost.p12", "changeit", null, null);
        get("/jwks", (request, response) -> {
            response.type("application/jwk-set+json");
            return jwkSet.toString();
        });
    }
}

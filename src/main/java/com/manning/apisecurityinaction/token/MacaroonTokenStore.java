package com.manning.apisecurityinaction.token;

import java.security.Key;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

import com.github.nitram509.jmacaroons.*;
import com.github.nitram509.jmacaroons.verifier.*;
import spark.Request;

public class MacaroonTokenStore implements SecureTokenStore {
    private final TokenStore delegate;
    private final Key macKey;

    private MacaroonTokenStore(TokenStore delegate, Key macKey) {
        this.delegate = delegate;
        this.macKey = macKey;
    }

    @Override
    public String create(Request request, Token token) {
        var identifier = delegate.create(request, token);
        var macaroon = MacaroonsBuilder.create("",
                macKey.getEncoded(), identifier);
        return macaroon.serialize();
    }

    public static SecureTokenStore wrap(
            ConfidentialTokenStore tokenStore, Key macKey) {
        return new MacaroonTokenStore(tokenStore, macKey);
    }

    public static AuthenticatedTokenStore wrap(
            TokenStore tokenStore, Key macKey) {
        return new MacaroonTokenStore(tokenStore, macKey);
    }

    @Override
    public Optional<Token> read(Request request, String tokenId) {
        var macaroon = MacaroonsBuilder.deserialize(tokenId);
        var verifier = new MacaroonsVerifier(macaroon);
        if (verifier.isValid(macKey.getEncoded())) {
            return delegate.read(request, macaroon.identifier);
        }
        return Optional.empty();
    }

    @Override
    public void revoke(Request request, String tokenId) {
        var macaroon = MacaroonsBuilder.deserialize(tokenId);
        delegate.revoke(request, macaroon.identifier);
    }

}
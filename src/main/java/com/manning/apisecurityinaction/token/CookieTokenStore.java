package com.manning.apisecurityinaction.token;

import java.util.Optional;
import spark.Request;

public class CookieTokenStore implements TokenStore {

  @Override
  public String create(Request request, Token token) {

    // WARNING: session fixation vulnerability!
    var session = request.session(true);

    session.attribute("username", token.username);
    session.attribute("expiry", token.expiry);
    session.attribute("attrs", token.attributes);

    return session.id();
  }

  @Override
  public Optional<Token> read(Request request, String tokenId) {

    var session = request.session(false);
    if (session == null) {
      return Optional.empty();
    }

    var token = new Token(session.attribute("expiry"),
        session.attribute("username"));
    token.attributes.putAll(session.attribute("attrs"));

    return Optional.of(token);
  }
}
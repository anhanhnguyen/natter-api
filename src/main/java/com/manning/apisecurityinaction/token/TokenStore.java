package com.manning.apisecurityinaction.token;

import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import spark.Request;

public interface TokenStore {
  String create(Request request, Token token);

  Optional<Token> read(Request request, String tokenId);

  class Token {
    public final Instant expiry;
    public final String username;
    public final Map<String, String> attributes;

    public Token(Instant expiry, String username) {
      this.expiry = expiry;
      this.username = username;
      this.attributes = new ConcurrentHashMap<>();
    }
  }
}
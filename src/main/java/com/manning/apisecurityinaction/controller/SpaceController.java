package com.manning.apisecurityinaction.controller;

import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Set;
import java.util.stream.Collectors;

import org.dalesbred.Database;
import org.json.JSONArray;
import org.json.JSONObject;

import spark.Request;
import spark.Response;

import java.net.*;
import java.net.http.*;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Pattern;

public class SpaceController {
  private final Database database;
  private final CapabilityController capabilityController;

  private static final Set<String> DEFINED_ROLES = Set.of("owner", "moderator", "member", "observer");

  public SpaceController(Database database, CapabilityController capabilityController) {
    this.database = database;
    this.capabilityController = capabilityController;
  }

  public JSONObject createSpace(Request request, Response response)
      throws SQLException {
    var json = new JSONObject(request.body());
    var spaceName = json.getString("name");
    if (spaceName.length() > 255) {
      throw new IllegalArgumentException("space name too long");
    }
    var owner = json.getString("owner");
    if (!owner.matches("[a-zA-Z][a-zA-Z0-9]{1,29}")) {
      throw new IllegalArgumentException("invalid username: " + owner);
    }

    var subject = request.attribute("subject");
    if (!owner.equals(subject)) {
      throw new IllegalArgumentException(
          "owner must match authenticated user");
    }

    return database.withTransaction(tx -> {
      var spaceId = database.findUniqueLong(
          "SELECT NEXT VALUE FOR space_id_seq;");

      database.updateUnique(
          "INSERT INTO spaces(space_id, name, owner) " +
              "VALUES(?, ?, ?);",
          spaceId, spaceName, owner);

      var expiry = Duration.ofDays(100000);
      var uri = capabilityController.createUri(request, "/spaces/" + spaceId, "rwd", expiry);
      var messagesUri = capabilityController.createUri(request, "/spaces/" + spaceId + "/messages", "rwd", expiry);
      var messagesReadWriteUri = capabilityController.createUri(request, "/spaces/" + spaceId + "/messages", "rw",
          expiry);
      var messagesReadOnlyUri = capabilityController.createUri(request, "/spaces/" + spaceId + "/messages", "r",
          expiry);

      response.status(201);
      response.header("Location", uri.toASCIIString());

      return new JSONObject()
          .put("name", spaceName)
          .put("uri", uri)
          .put("messages-rwd", messagesUri)
          .put("messages-rw", messagesReadWriteUri)
          .put("messages-r", messagesReadOnlyUri);
    });
  }

  public JSONObject postMessage(Request request, Response response)
      throws SQLException {
    var json = new JSONObject(request.body());

    var author = json.getString("author");
    if (!author.matches("[a-zA-Z][a-zA-Z0-9]{1,29}")) {
      throw new IllegalArgumentException("invalid username: " + author);
    }

    var subject = request.attribute("subject");
    if (!author.equals(subject)) {
      throw new IllegalArgumentException(
          "author must match authenticated user");
    }

    return database.withTransaction(tx -> {
      var spaceId = Long.parseLong(request.params(":spaceId"));
      var msgId = database.findUniqueLong("SELECT NEXT VALUE FOR msg_id_seq;");
      var message = json.getString("message");

      database.updateUnique(
          "INSERT INTO messages(space_id, msg_id, msg_time," +
              "author, msg_text) " +
              "VALUES(?, ?, current_timestamp, ?, ?)",
          spaceId, msgId, author, message);

      response.status(201);

      var uri = capabilityController.createUri(request, "/spaces/" + spaceId + "/messages/" + msgId, "rd",
          Duration.ofMinutes(5));
      var readOnlyUri = capabilityController.createUri(request, "/spaces/" + spaceId + "/messages/" + msgId, "r",
          Duration.ofDays(365));

      return new JSONObject()
          .put("message", message)
          .put("uri", uri)
          .put("read-only", readOnlyUri);
    });
  }

  public JSONArray findMessages(Request request, Response response) {
    var since = Instant.now().minus(1, ChronoUnit.DAYS);
    if (request.queryParams("since") != null) {
      since = Instant.parse(request.queryParams("since"));
    }
    var spaceId = Long.parseLong(request.params(":spaceId"));

    var messages = database.findAll(Long.class,
        "SELECT msg_id FROM messages " +
            "WHERE space_id = ? AND msg_time >= ?;",
        spaceId, since);

    var perms = request.<String>attribute("perms")
        .replace("w", "");
    response.status(200);
    return new JSONArray(messages.stream()
        .map(msgId -> "/spaces/" + spaceId + "/messages/" + msgId)
        .map(path -> capabilityController.createUri(request, path, perms, Duration.ofMinutes(10)))
        .collect(Collectors.toList()));
  }

  public JSONObject addMember(Request request, Response response) {
    var json = new JSONObject(request.body());
    var spaceId = Long.parseLong(request.params(":spaceId"));
    var userToAdd = json.getString("username");
    var role = json.optString("role", "member");

    if (!DEFINED_ROLES.contains(role)) {
      throw new IllegalArgumentException("invalid role");
    }

    database.updateUnique(
        "INSERT INTO user_roles(space_id, user_id, role_id)" +
            " VALUES(?, ?, ?)",
        spaceId, userToAdd, role);

    response.status(200);
    return new JSONObject()
        .put("username", userToAdd)
        .put("role", role);
  }

  public JSONObject deleteMessage(Request request, Response response) {
    var spaceId = Long.parseLong(request.params(":spaceId"));
    var msgId = Long.parseLong(request.params(":msgId"));

    database.updateUnique("DELETE FROM messages WHERE space_id = ? AND msg_id = ?", spaceId, msgId);
    response.status(200);
    return new JSONObject();
  }

  private final HttpClient httpClient = HttpClient.newHttpClient();
  private final URI linkPreviewService = URI.create("http://natter-link-preview-service:4567");

  private JSONObject fetchLinkPreview(String link) {
    var url = linkPreviewService.resolve("/preview?url=" + URLEncoder.encode(link, StandardCharsets.UTF_8));
    var request = HttpRequest.newBuilder(url).GET().build();
    try {
      var response = httpClient.send(request, BodyHandlers.ofString());
      if (response.statusCode() == 200) {
        return new JSONObject(response.body());
      }
    } catch (Exception ignored) {
    }
    return null;
  }

  public static class Message {
    private final long spaceId;
    private final long msgId;
    private final String author;
    private final Instant time;
    private final String message;
    private final List<JSONObject> links = new ArrayList<>();

    public Message(long spaceId, long msgId, String author,
        Instant time, String message) {
      this.spaceId = spaceId;
      this.msgId = msgId;
      this.author = author;
      this.time = time;
      this.message = message;
    }

    @Override
    public String toString() {
      JSONObject msg = new JSONObject();
      msg.put("uri",
          "/spaces/" + spaceId + "/messages/" + msgId);
      msg.put("author", author);
      msg.put("time", time.toString());
      msg.put("message", message);
      msg.put("links", links);
      return msg.toString();
    }
  }

  public Message readMessage(Request request, Response response) {
    var spaceId = Long.parseLong(request.params(":spaceId"));
    var msgId = Long.parseLong(request.params(":msgId"));

    var message = database.findUnique(Message.class,
        "SELECT space_id, msg_id, author, msg_time, msg_text " +
            "FROM messages WHERE msg_id = ? AND space_id = ?",
        msgId, spaceId);

    var linkPattern = Pattern.compile("https?://\\S+");
    var matcher = linkPattern.matcher(message.message);
    int start = 0;
    while (matcher.find(start)) {
      var url = matcher.group();
      System.out.println(url);
      var preview = fetchLinkPreview(url);
      if (preview != null) {
        message.links.add(preview);
      }
      start = matcher.end();
    }

    response.status(200);
    return message;
  }
}
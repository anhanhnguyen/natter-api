package com.manning.apisecurityinaction.controller;

import java.sql.SQLException;
import java.time.Duration;
import java.util.Set;

import org.dalesbred.Database;
import org.json.JSONObject;

import spark.Request;
import spark.Response;

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
      var messagesReadWriteUri = capabilityController.createUri(request, "/spaces/" + spaceId + "/messages", "rw", expiry);
      var messagesReadOnlyUri = capabilityController.createUri(request, "/spaces/" + spaceId + "/messages", "r", expiry);

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

      return new JSONObject()
          .put("message", message)
          .put("uri", "/spaces/" + spaceId + "/messages/" + msgId);
    });
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
}
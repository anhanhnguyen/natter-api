package com.manning.apisecurityinaction.controller;

import java.sql.SQLException;

import org.dalesbred.Database;
import org.json.*;
import spark.*;

public class SpaceController {
  private final Database database;

  public SpaceController(Database database) {
    this.database = database;
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

      database.updateUnique(
          "INSERT INTO permissions(space_id, user_id, perms) " +
              "VALUES(?, ?, ?)",
          spaceId, owner, "rwd");

      response.status(201);
      response.header("Location", "/spaces/" + spaceId);

      return new JSONObject()
          .put("name", spaceName)
          .put("uri", "/spaces/" + spaceId);
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
    var perms = json.getString("permissions");

    if (!perms.matches("r?w?d?")) {
      throw new IllegalArgumentException("invalid permissions");
    }

    database.updateUnique(
        "INSERT INTO permissions(space_id, user_id, perms) " +
            "VALUES(?, ?, ?);",
        spaceId, userToAdd, perms);

    response.status(200);
    return new JSONObject()
        .put("username", userToAdd)
        .put("permissions", perms);
  }
}
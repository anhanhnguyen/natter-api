package com.manning.apisecurityinaction;

import com.manning.apisecurityinaction.controller.*;
import org.dalesbred.Database;
import org.h2.jdbcx.JdbcConnectionPool;
import org.json.*;

import java.nio.file.*;
import com.google.common.util.concurrent.*;

import org.dalesbred.result.EmptyResultException;
import spark.*;

import static spark.Spark.*;

public class Main {

  public static void main(String... args) throws Exception {
    secure("localhost.p12", "changeit", null, null);

    var datasource = JdbcConnectionPool.create(
        "jdbc:h2:mem:natter", "natter", "password");
    var database = Database.forDataSource(datasource);
    createTables(database);
    datasource = JdbcConnectionPool.create(
        "jdbc:h2:mem:natter", "natter_api_user", "password");
    database = Database.forDataSource(datasource);

    var spaceController = new SpaceController(database);
    var userController = new UserController(database);
    var auditController = new AuditController(database);

    var rateLimiter = RateLimiter.create(2.0d);

    before((request, response) -> {
      if (!rateLimiter.tryAcquire()) {
        halt(429);
      }
    });

    before(((request, response) -> {
      if (request.requestMethod().equals("POST") &&
          !"application/json".equals(request.contentType())) {
        halt(415, new JSONObject().put(
            "error", "Only application/json supported").toString());
      }
    }));

    afterAfter((request, response) -> {
      response.type("application/json;charset=utf-8");
      response.header("X-Content-Type-Options", "nosniff");
      response.header("X-Frame-Options", "DENY");
      response.header("X-XSS-Protection", "0");
      response.header("Cache-Control", "no-store");
      response.header("Content-Security-Policy",
          "default-src 'none'; frame-ancestors 'none'; sandbox");
      response.header("Server", "");
      response.header("Strict-Transport-Security", "max-age=31536000");
    });

    before(userController::authenticate);

    before(auditController::auditRequestStart);
    afterAfter(auditController::auditRequestEnd);

    get("/logs", auditController::readAuditLog);

    post("/users", userController::registerUser);

    before("/spaces", userController::requireAuthentication);
    post("/spaces", spaceController::createSpace);

    before("/spaces/:spaceId/messages", userController.requirePermission("POST", "w"));
    post("/spaces/:spaceId/messages", spaceController::postMessage);

    before("/spaces/:spaceId/messages/*", userController.requirePermission("DELETE", "d"));
    delete("/spaces/:spaceId/messages/:msgId", spaceController::deleteMessage);

    before("/spaces/:spaceId/members", userController.requirePermission("POST", "w"));
    post("/spaces/:spaceId/members", spaceController::addMember);

    internalServerError(new JSONObject()
        .put("error", "internal server error").toString());
    notFound(new JSONObject()
        .put("error", "not found").toString());

    exception(IllegalArgumentException.class, Main::badRequest);
    exception(JSONException.class, Main::badRequest);
  }

  private static void badRequest(Exception ex,
      Request request, Response response) {
    response.status(400);
    response.body(new JSONObject()
        .put("error", ex.getMessage()).toString());
  }

  private static void createTables(Database database)
      throws Exception {
    var path = Paths.get(
        Main.class.getResource("/schema.sql").toURI());
    database.update(Files.readString(path));
  }
}
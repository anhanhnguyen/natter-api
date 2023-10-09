package com.manning.apisecurityinaction;

import com.manning.apisecurityinaction.controller.*;
import org.dalesbred.Database;
import org.h2.jdbcx.JdbcConnectionPool;
import org.json.*;

import java.nio.file.*;

import org.dalesbred.result.EmptyResultException;
import spark.*;

import static spark.Spark.*;

public class Main {

  public static void main(String... args) throws Exception {
    var datasource = JdbcConnectionPool.create(
        "jdbc:h2:mem:natter", "natter", "password");
    var database = Database.forDataSource(datasource);
    createTables(database);
    datasource = JdbcConnectionPool.create(
        "jdbc:h2:mem:natter", "natter_api_user", "password");
    database = Database.forDataSource(datasource);

    var spaceController = new SpaceController(database);
    post("/spaces",
        spaceController::createSpace);

    after((request, response) -> {
      response.type("application/json");
    });

    afterAfter((request, response) ->
          response.header("Server", ""));

    internalServerError(new JSONObject()
        .put("error", "internal server error").toString());
    notFound(new JSONObject()
        .put("error", "not found").toString());

    exception(IllegalArgumentException.class,
        Main::badRequest);
    exception(JSONException.class,
        Main::badRequest);
    exception(EmptyResultException.class,
        (e, request, response) -> response.status(404));
  }

  private static void badRequest(Exception ex,
      Request request, Response response) {
    response.status(400);
    response.body("{\"error\": \"" + ex.getMessage() + "\"}");
  }

  private static void createTables(Database database)
      throws Exception {
    var path = Paths.get(
        Main.class.getResource("/schema.sql").toURI());
    database.update(Files.readString(path));
  }
}
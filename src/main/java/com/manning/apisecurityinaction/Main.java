package com.manning.apisecurityinaction;

import com.manning.apisecurityinaction.controller.*;
import com.manning.apisecurityinaction.controller.ABACAccessController.Decision;
import com.manning.apisecurityinaction.token.CookieTokenStore;
import com.manning.apisecurityinaction.token.DatabaseTokenStore;
import com.manning.apisecurityinaction.token.EncryptedJwtTokenStore;
import com.manning.apisecurityinaction.token.EncryptedTokenStore;
import com.manning.apisecurityinaction.token.HmacTokenStore;
import com.manning.apisecurityinaction.token.JsonTokenStore;
import com.manning.apisecurityinaction.token.MacaroonTokenStore;
import com.manning.apisecurityinaction.token.OAuth2TokenStore;
import com.manning.apisecurityinaction.token.SecureTokenStore;
import com.manning.apisecurityinaction.token.SignedJwtTokenStore;
import com.manning.apisecurityinaction.token.TokenStore;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;

import software.pando.crypto.nacl.SecretBox;

import org.dalesbred.Database;
import org.h2.jdbcx.JdbcConnectionPool;
import org.json.*;
import org.kie.api.runtime.KieSession;

import java.io.FileInputStream;
import java.net.URI;
import java.nio.file.*;
import java.security.KeyStore;

import com.google.common.util.concurrent.*;

import org.dalesbred.result.EmptyResultException;
import spark.*;

import static spark.Spark.*;
import java.util.Set;

import javax.crypto.SecretKey;

public class Main {

  public static void main(String... args) throws Exception {
    Spark.staticFiles.location("/public");
    // secure("localhost.p12", "changeit", null, null);
    port(args.length > 0 ? Integer.parseInt(args[0]) : spark.Service.SPARK_DEFAULT_PORT);

    var secretsPath = Paths.get("/etc/secrets/database");
    var dbUsername = Files.readString(secretsPath.resolve("username"));
    var dbPassword = Files.readString(secretsPath.resolve("password"));

    var jdbcUrl = "jdbc:h2:tcp://natter-database-service:9092/mem:natter";
    var datasource = JdbcConnectionPool.create(jdbcUrl, dbUsername, dbPassword);
    createTables(Database.forDataSource(datasource));
    datasource = JdbcConnectionPool.create(jdbcUrl, "natter_api_user", "password");
    var database = Database.forDataSource(datasource);

    var keyPassword = System.getProperty("keystore.password", "changeit").toCharArray();
    var keyStore = KeyStore.getInstance("PKCS12");
    keyStore.load(new FileInputStream("keystore.p12"), keyPassword);
    var macKey = keyStore.getKey("hmac-key", keyPassword);
    var encKey = HKDF.expand(macKey, "token-encryption-key", 32, "AES");

    var capController = new CapabilityController(MacaroonTokenStore.wrap(new DatabaseTokenStore(database), macKey));
    var spaceController = new SpaceController(database, capController);
    var userController = new UserController(database);
    var auditController = new AuditController(database);

    var rateLimiter = RateLimiter.create(2.0d);

    before((request, response) -> {
      if (!rateLimiter.tryAcquire()) {
        halt(429);
      }
    });
    before(new CorsFilter(Set.of("https://localhost:9999")));

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

    SecureTokenStore tokenStore = new CookieTokenStore();
    var tokenController = new TokenController(tokenStore);

    before(userController::authenticate);
    before(tokenController::validateToken);

    before(auditController::auditRequestStart);
    afterAfter(auditController::auditRequestEnd);

    // var droolsController = new DroolsAccessController();
    // before("/*", droolsController::enforcePolicy);

    get("/logs", auditController::readAuditLog);

    post("/capabilities", capController::share);

    before("/sessions", userController::requireAuthentication);
    before("/sessions", tokenController.requireScope("POST", "full_access"));
    post("/sessions", tokenController::login);
    delete("/sessions", tokenController::logout);

    before("/expired_tokens", userController::requireAuthentication);
    // delete("/expired_tokens", (request, response) -> {
    // databaseTokenStore.deleteExpiredTokens();
    // return new JSONObject();
    // });

    post("/users", userController::registerUser);

    before("/spaces", userController::requireAuthentication);
    before("/spaces", tokenController.requireScope("POST", "create_space"));
    post("/spaces", spaceController::createSpace);

    before("/spaces/:spaceId/messages", capController::lookupPermissions);
    before("/spaces/:spaceId/messages/*", capController::lookupPermissions);
    before("/spaces/:spaceId/members", capController::lookupPermissions);

    before("/spaces/*/messages", tokenController.requireScope("POST", "post_message"));
    before("/spaces/:spaceId/messages", userController.requirePermission("POST", "w"));
    post("/spaces/:spaceId/messages", spaceController::postMessage);

    before("/spaces/*/messages/*", tokenController.requireScope("GET", "read_message"));
    before("/spaces/:spaceId/messages/*", userController.requirePermission("GET", "r"));
    get("/spaces/:spaceId/messages/:msgId", spaceController::readMessage);

    before("/spaces/*/messages", tokenController.requireScope("GET", "list_messages"));
    before("/spaces/:spaceId/messages", userController.requirePermission("GET", "r"));
    get("/spaces/:spaceId/messages", spaceController::findMessages);

    before("/spaces/*/members", tokenController.requireScope("POST", "add_member"));
    before("/spaces/:spaceId/members", userController.requirePermission("POST", "rwd"));
    post("/spaces/:spaceId/members", spaceController::addMember);

    before("/spaces/*/messages/*", tokenController.requireScope("DELETE", "delete_message"));
    before("/spaces/:spaceId/messages/*", userController.requirePermission("DELETE", "d"));

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
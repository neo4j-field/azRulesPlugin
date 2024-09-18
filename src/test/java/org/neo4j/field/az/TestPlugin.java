package org.neo4j.field.az;

import com.google.common.base.Splitter;
import com.neo4j.configuration.SecuritySettings;
import com.neo4j.configuration.SecuritySettings.OidcAuthFlow;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.neo4j.configuration.GraphDatabaseSettings;
import org.neo4j.driver.AuthTokens;
import org.neo4j.driver.Driver;
import org.neo4j.driver.GraphDatabase;
import org.neo4j.driver.Session;
import org.neo4j.logging.Level;
import org.neo4j.logging.Log;
import org.neo4j.logging.log4j.Log4jLogProvider;
import com.neo4j.harness.EnterpriseNeo4jBuilders;
import io.undertow.Undertow;
import io.undertow.io.IoCallback;
import io.undertow.server.handlers.resource.PathResourceManager;
import io.undertow.server.handlers.resource.Resource;
import io.undertow.server.handlers.resource.ResourceManager;
import io.undertow.util.Headers;
import io.undertow.util.MimeMappings;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import static org.hamcrest.CoreMatchers.hasItems;
import static org.hamcrest.MatcherAssert.assertThat;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;
import static org.junit.jupiter.api.Assertions.assertFalse;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.neo4j.harness.Neo4j;

/**
 * Test plugin using harness
 * @author garymann
 */
@TestInstance(Lifecycle.PER_CLASS)
public class TestPlugin {
    
    File resourcesDirectory = new File("src/test/resources");
    String logConfig = resourcesDirectory.getAbsolutePath() + "/server-logs.xml"; 
    static Log4jLogProvider logProvider = new Log4jLogProvider(System.out);
    Log log = logProvider.getLog(TestPlugin.class);
    private Neo4j neo4j;
    RsaJsonWebKey rsaJsonWebKey;
    Undertow server;
    
    private Map<String, String> parseMap(String m) {
        log.debug("parse:" + m);
        return Splitter.on(';').withKeyValueSeparator('=').split(m);
    }
    
    private String getGoodLightAccessToken() throws JoseException {
        JwtClaims claims = new JwtClaims();
        claims.setIssuer("neo4j-sso");
        claims.setAudience("neo4j-sso");
        claims.setExpirationTimeMinutesInTheFuture(10);
        claims.setGeneratedJwtId();
        claims.setIssuedAtToNow();
        claims.setNotBeforeMinutesInThePast(2);
        claims.setSubject("testsub");
        //claims.setClaim("email", "test@neo4j.com");
        //claims.setClaim("empType", "staff");
        //List<String> roles = Arrays.asList("role1", "role3", "role5");
        //claims.setStringListClaim("roles", roles);
        
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(rsaJsonWebKey.getPrivateKey());
        jws.setKeyIdHeaderValue(rsaJsonWebKey.getKeyId());
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        String jwt = jws.getCompactSerialization();
        return jwt;
    }
    
    // without iat
    private String getGoodLightAccessToken2() throws JoseException {
        JwtClaims claims = new JwtClaims();
        claims.setIssuer("neo4j-sso");
        claims.setAudience("neo4j-sso");
        claims.setExpirationTimeMinutesInTheFuture(10);
        claims.setGeneratedJwtId();
        //claims.setIssuedAtToNow();
        claims.setNotBeforeMinutesInThePast(2);
        claims.setSubject("testsub");
        
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(rsaJsonWebKey.getPrivateKey());
        jws.setKeyIdHeaderValue(rsaJsonWebKey.getKeyId());
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        String jwt = jws.getCompactSerialization();
        return jwt;
    }
    
    private void setJWKs() {
        String j = rsaJsonWebKey.toJson();
        try {
            String x = "{\"keys\":[" + j + "]}";
            log.debug("json web key:" + x);
            FileWriter file;
            file = new FileWriter(resourcesDirectory.getAbsolutePath() + "/jwks.json");
            file.write(x);
            file.close();
        } catch (IOException e) {
            log.error("Can't write JWKS");
        }
    }
    
    @BeforeAll
    public void setup() {
        logProvider.updateLogLevel(Level.DEBUG);
        Path logConfigPath = Paths.get(logConfig);
        Path logPath = Paths.get(resourcesDirectory.getAbsolutePath());
        
        // webserver for sso files
        server = Undertow.builder()
        .addHttpListener(3000, "localhost")
        .setHandler(exchange -> {
            exchange.getResponseHeaders().put(Headers.CONTENT_TYPE, "application/json");
            ResourceManager manager = new PathResourceManager(Paths.get(resourcesDirectory.getAbsolutePath()));
            Resource resource = manager.getResource(exchange.getRelativePath());
            if(null == resource.getContentType(MimeMappings.DEFAULT)) resource = manager.getResource("/index.html");
            exchange.getResponseHeaders().put(Headers.CONTENT_TYPE, resource.getContentType(MimeMappings.DEFAULT));
            resource.serve(exchange.getResponseSender(), exchange, IoCallback.END_EXCHANGE);
        }).build();
        
        server.start();
        
        try {
            // generate and write a key for the tokens
            rsaJsonWebKey = RsaJwkGenerator.generateJwk(2048);
            rsaJsonWebKey.setKeyId("k1");
            setJWKs();
            
            // test neo4j harness
            neo4j = EnterpriseNeo4jBuilders.newInProcessBuilder()
                    .withConfig(GraphDatabaseSettings.auth_enabled, true)
                    .withConfig(SecuritySettings.authentication_providers, Collections.singletonList("plugin-org.neo4j.field.az.AzRulesAzPlugin"))
                    .withConfig(SecuritySettings.authorization_providers, Collections.singletonList("plugin-org.neo4j.field.az.AzRulesAzPlugin"))
                    .withConfig(AzRulesSettings.add_idp_roles_groups, false)
                    .withConfig(SecuritySettings.ldap_authorization_group_to_role_mapping, "(roles:role1&&roles:role5)=admin;roles:\"cn=xxx, ou=yyy, c=u.s.\"=role66;empType:staff=staffrole")
                    .withConfig(SecuritySettings.OIDCSetting.forProvider("testrealm").display_name, "Test")
                    .withConfig(SecuritySettings.OIDCSetting.forProvider("testrealm").auth_flow, OidcAuthFlow.PKCE)
                    .withConfig(SecuritySettings.OIDCSetting.forProvider("testrealm").well_known_discovery_uri, new URI("http://localhost:3000/wkd.json"))
                    .withConfig(SecuritySettings.OIDCSetting.forProvider("testrealm").params, parseMap("client_id=neo4j-sso;response_type=code;scope=openid email roles"))
                    .withConfig(SecuritySettings.OIDCSetting.forProvider("testrealm").config, parseMap("token_type_principal=access_token;token_type_authentication=access_token"))
                    .withConfig(SecuritySettings.OIDCSetting.forProvider("testrealm").issuer, "neo4j-sso")
                    .withConfig(SecuritySettings.OIDCSetting.forProvider("testrealm").client_id, "neo4j-sso")
                    .withConfig(SecuritySettings.OIDCSetting.forProvider("testrealm").audience, List.of("neo4j-sso"))
                    .withConfig(SecuritySettings.OIDCSetting.forProvider("testrealm").username_claim, "sub")
                    .withConfig(SecuritySettings.OIDCSetting.forProvider("testrealm").groups_claim, "roles")
                    .withConfig(SecuritySettings.OIDCSetting.forProvider("testrealm").get_groups_from_user_info, true)
                    .withConfig(SecuritySettings.OIDCSetting.forProvider("testrealm").get_username_from_user_info, false)
                    .withConfig(GraphDatabaseSettings.strict_config_validation, false)
                    .withConfig(GraphDatabaseSettings.server_logging_config_path, logConfigPath)
                    .withConfig(GraphDatabaseSettings.logs_directory, logPath)
                    .withConfig(AzRulesSettings.require_iat_claim, false)
                    .withDisabledServer()
                    .build();
            
            log.debug("Neo4j::" + neo4j);        
        } catch (URISyntaxException|JoseException e) {
            e.printStackTrace();
        }
    }
    
    @Test
    public void test1() {
        log.debug("Test1");
        //neo4j.printLogs(System.out);
        try (Driver driver = GraphDatabase.driver(neo4j.boltURI(), AuthTokens.basic("testsub", getGoodLightAccessToken()))) {
            try (Session session = driver.session()) {
                long result = session.run("return 1").single().get(0).asLong();
                assertEquals(1l, result);
            }
        } catch (Exception e) {
            e.printStackTrace();
            assertFalse(true);
        }
    }
    
    @Test
    public void test2() {
        log.debug("Test2");
        try (Driver driver = GraphDatabase.driver(neo4j.boltURI(), AuthTokens.basic("testsub", getGoodLightAccessToken()))) {
            try (Session session = driver.session()) {
                List<Object> result = session.run("SHOW CURRENT USER YIELD roles").single().get(0).asList();
                assertThat(result, hasItems("admin"));
            }
        } catch (Exception e) {
            e.printStackTrace();
            assertFalse(true);
        }
    }
    
    @Test
    public void test3() {
        log.debug("Test3");
        try ( Driver driver = GraphDatabase.driver(neo4j.boltURI(), AuthTokens.basic("testsub", getGoodLightAccessToken2()))) {
            try ( Session session = driver.session()) {
                List<Object> result = session.run("SHOW CURRENT USER YIELD roles").single().get(0).asList();
                assertThat(result, hasItems("admin"));
            }
        } catch (Exception e) {
            e.printStackTrace();
            assertFalse(true);
        }
    }
    
    @AfterAll
    public void stopNeo4j() {
        if (neo4j != null) {
            neo4j.printLogs(System.out);
            neo4j.close();
        }
        if (server != null) {
            server.stop();
        }
    }
}

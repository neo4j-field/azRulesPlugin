package org.neo4j.field.az;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.neo4j.server.security.enterprise.auth.plugin.api.AuthProviderOperations;
import java.util.Collection;
import java.util.Collections;
import org.neo4j.configuration.Config;
import com.neo4j.configuration.SecuritySettings;
import com.neo4j.server.security.enterprise.auth.MessageConstants;
import com.neo4j.server.security.enterprise.auth.OidcAuthInfo;
import com.neo4j.server.security.enterprise.auth.OidcSettings;
import com.neo4j.server.security.enterprise.auth.plugin.api.AuthToken;
import com.neo4j.server.security.enterprise.auth.plugin.api.AuthenticationException;
import com.neo4j.server.security.enterprise.auth.plugin.spi.AuthInfo;
import com.neo4j.server.security.enterprise.auth.plugin.spi.AuthPlugin;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import static javax.ws.rs.core.HttpHeaders.ACCEPT;
import static javax.ws.rs.core.MediaType.APPLICATION_JSON;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver;
import org.jose4j.lang.JoseException;
import org.jose4j.lang.JsonHelp;
import org.neo4j.common.DependencyResolver;
import org.neo4j.graphdb.security.AuthTokenExpiredException;
import org.neo4j.internal.kernel.api.security.AuthenticationResult;
import org.neo4j.kernel.internal.GraphDatabaseAPI;
import org.neo4j.logging.InternalLog;
import org.neo4j.scheduler.JobScheduler;
import org.neo4j.server.security.auth.ValidityCheck;

/**
 * TODO - az caching setup
 * TODO - exceptions
 */
public class AzRulesAzPlugin extends AuthPlugin.Adapter {
    private AuthProviderOperations api = null;
    private Config config = null;
    private JwtConsumer parsingJwtConsumer = null;
    private JwtConsumer validatingJwtConsumer = null;
    private OidcSettings settings = null;
    private Cache<String, UserInfo> userInfoAuthTokenCache;
    private InternalLog intLog = null; 
    private final HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(30)).build();

    @Override
    public void initialize(AuthProviderOperations apo) {
        api = apo;
        parsingJwtConsumer = new JwtConsumerBuilder()
                .setDisableRequireSignature()
                .setSkipSignatureVerification()
                .setSkipAllValidators()
                .build();

        api.setAuthenticationCachingEnabled(false);
        api.setAuthorizationCachingEnabled(true);
        //api.setCredentialsMatcher(new AllowAllCredentialsMatcher());
    }

    @Override
    public void start() {
        intLog = ExposeConfigExtensionFactory.logsvc.getInternalLog(AzRulesAzPlugin.class);
        intLog.info("Starting az rules plugin");
        config = ExposeConfigExtensionFactory.config;

        GraphDatabaseAPI db = ExposeConfigExtensionFactory.db;
        DependencyResolver dr = db.getDependencyResolver();
        JobScheduler gm = dr.resolveDependency(JobScheduler.class);

        // we're only planning for one provider
        List<OidcSettings> oidcSettingsList = config.getGroups(SecuritySettings.OIDCSetting.class).values().stream()
                .map(oidcSetting -> new OidcSettings(config, oidcSetting, ExposeConfigExtensionFactory.logsvc.getInternalLogProvider(), gm))
                .collect(Collectors.toList());
        settings = oidcSettingsList.get(0);
        int maxCapacity = config.get(SecuritySettings.auth_cache_max_capacity);
        long ttl = config.get(SecuritySettings.auth_cache_ttl).toMillis();
        userInfoAuthTokenCache = Caffeine.newBuilder().expireAfterWrite(1, TimeUnit.DAYS)
                .maximumSize(maxCapacity)
                .expireAfterAccess(Duration.ofSeconds(ttl)).build();
        buildValidatingJWTConsumer(settings.getIssuer(), settings.getAudience(), settings.getJwksUri());
    }

    @Override
    public AuthInfo authenticateAndAuthorize(AuthToken token) throws AuthenticationException {
        String username = token.principal();
        intLog.debug("Received Principal for AA: " + username);
        Map<String, String> ssoConfig = settings.getOidcConfig();
        intLog.debug("Validating User token: " + token);
        OidcAuthInfo info = validateToken(token);
        // Caching should happen
        return AuthInfo.of(info.getPrincipals().getPrimaryPrincipal(), info.getRoles());
    }

    private OidcAuthInfo validateToken(AuthToken authToken) {
        try {
            intLog.debug("Parsing Token for user: " + authToken.principal() + " ,token:"  + new String(authToken.credentials()));
            JwtClaims jwtClaims = jwtClaims = parsingJwtConsumer.processToClaims(new String(authToken.credentials()));
            intLog.debug("Parsed Token with Claims: " + jwtClaims);
            if (settings.getIssuer() != null && settings.getIssuer().equals(jwtClaims.getIssuer())) {
                try {
                    jwtClaims = validatingJwtConsumer.processToClaims(new String(authToken.credentials()));
                    intLog.debug("Validated Token with Claims: " + jwtClaims);
                    String username = getUsername(authToken, jwtClaims);
                    intLog.debug("Username: " + username);
                    //Set<String> roles = Set.of();
                    Set<String> roles = getRoles(authToken, jwtClaims);
                    OidcAuthInfo authInfo = new OidcAuthInfo(
                            username,
                            getName(),
                            AuthenticationResult.SUCCESS,
                            roles,
                            List.of(new TokenExpiryCheck(jwtClaims.getExpirationTime(), 30)));
                    //api.cacheAuthorizationInfo(authInfo);
                    api.log().info("Successfully authenticated user:" + username + " with roles:" + roles);
                    return authInfo;
                } catch (InvalidJwtException e) {
                    JwtClaims claimsFromException = e.getJwtContext().getJwtClaims();
                    Object user = claimsFromException != null
                            ? claimsFromException.getClaimValue(settings.getUsernameClaimName())
                            : "<unknown>";
                    // Log if JWT has expired
                    if (e.hasExpired()) {
                        api.log().warn("User :" + user + " attempted to log in with expired token");
                        return null;
                    }
                    intLog.error("Error - user:" + user + "Exception:" + e);
                }
            } else {
                String error = String.format("Received a JWT with issuer '%s' but was expecting '%s'. If there is only one OpenId Connect provider configured, "
                        + "this is likely a configuration error. Otherwise it can be ignored as the token is likely intended for a different "
                        + "provider configuration.",jwtClaims.getIssuer(), settings.getIssuer() == null ? "<unconfigured>" : settings.getIssuer());
                intLog.debug(error);
            }
        } catch (InvalidJwtException e) {
            // We didn't manage to parse this, so it's probably not a JWT and therefore assume it's for some other realm
            // and not for us.
            intLog.debug("Failed to authenticate. Could not parse JWT.");
        } catch (Exception e) {
            String error = String.format("Failed to authenticate user info: %s, caused by %s", e.getMessage(), e.getCause() == null ? "" : e.getMessage());
            intLog.debug(error, e);
            api.log().warn(error);
        }

        return null;
    }
    
    private String getUsername(AuthToken authToken, JwtClaims jwtClaims)
            throws IOException, InterruptedException, JoseException, AuthenticationException {
        if ( settings.shouldGetUsernameFromUserInfo()) {
            UserInfo userInfo = userInfoAuthTokenCache.getIfPresent(authToken.toString());
            if (userInfo == null) {
                userInfo = fetchAndCacheUserInfo(authToken);
            }
            return userInfo.token();
        } else {
            Object userClaim = jwtClaims.getClaimValue(settings.getUsernameClaimName());
            if (!(userClaim instanceof String)) {
                throw new IllegalArgumentException(String.format("JWT user claim must be a string, instead was '%s'", userClaim));
            }
            return (String) userClaim;
        }
    }
        
    private void buildValidatingJWTConsumer(String iss, String[] aud, URI jwks) {
        JwtConsumerBuilder jwtConsumerBuilder = new JwtConsumerBuilder()
                .setRequireExpirationTime()
                .setAllowedClockSkewInSeconds(30)
                .setRequireSubject()
                .setExpectedIssuer(iss)
                .setExpectedAudience(aud)
                .setEnableRequireIntegrity()
                //.setRequireIssuedAt()
                .setIssuedAtRestrictions(0, Integer.MAX_VALUE);
        // make iat requirement configurable
        if (config.get(AzRulesSettings.require_iat_claim) == true) {
            jwtConsumerBuilder.setRequireIssuedAt();
        }

        if (jwks != null) {
            HttpsJwks httpsJkws = new HttpsJwks(jwks.toString());
            HttpsJwksVerificationKeyResolver httpsJwksKeyResolver = new HttpsJwksVerificationKeyResolver(httpsJkws);
            jwtConsumerBuilder.setVerificationKeyResolver(httpsJwksKeyResolver);
        }
        validatingJwtConsumer = jwtConsumerBuilder.build();
    }

    private Set<String> getRoles(AuthToken authToken, JwtClaims jwtClaims)
            throws JoseException, IOException, InterruptedException, AuthenticationException {
        Set<String> roles = new HashSet<>();
        intLog.debug("Getting roles getRoles");
        Map<String, Object> allClaims = getAllClaims(authToken, jwtClaims);
        SecuritySettings.OIDCSetting stsConfig = SecuritySettings.OIDCSetting.forProvider(settings.getProviderName());
        AzRulesGroupRoleMapping groupToRoleMapping = new AzRulesGroupRoleMapping(config.get(SecuritySettings.ldap_authorization_group_to_role_mapping), intLog);
        if (groupToRoleMapping != null) {
            intLog.debug("AllClaims:" + allClaims);
            Collection<String> mappedGroups = groupToRoleMapping.get(allClaims);
            intLog.debug("mappedGroups::" + mappedGroups);
            if (mappedGroups != null) {
                roles.addAll(mappedGroups);
            }
        }
        // add idp roles/groups if configured
        if (config.get(AzRulesSettings.add_idp_roles_groups)) {
            //roles.addAll((Collection<? extends String>) jwtClaims.getClaimValue(settings.getGroupsClaimName()));
            Collection<String> idpRoles = parseTokenClaims(allClaims.get(settings.getGroupsClaimName()));
            intLog.debug("idpRoles:" + idpRoles);
            if (idpRoles != null && idpRoles.size() > 0) {
                roles.addAll((Collection<? extends String>) allClaims.get(settings.getGroupsClaimName()));
            }
        }
        intLog.debug("resolved roles:" + roles);
        return roles;
    }

    @SuppressWarnings("unchecked")
    private Collection<String> getTokenRoles(AuthToken authToken, JwtClaims jwtClaims)
            throws IOException, InterruptedException, JoseException, AuthenticationException {
        if (settings.shouldGetGroupsFromUserInfo()) {
            UserInfo userInfo = userInfoAuthTokenCache.getIfPresent(authToken.toString());

            if (userInfo == null) {
                userInfo = fetchAndCacheUserInfo(authToken);
            }
            return userInfo.groups();
        } else {
            Object groupsClaim = jwtClaims.getClaimValue(settings.getGroupsClaimName());
            return parseTokenClaims(groupsClaim);
        }
    }
    
    private Map<String, Object> getAllClaims(AuthToken authToken, JwtClaims jwtClaims) 
            throws IOException, InterruptedException, JoseException, AuthenticationException  {      
        Map<String, Object> c = jwtClaims.getClaimsMap();
        if (settings.shouldGetGroupsFromUserInfo()) {
            UserInfo userInfo = userInfoAuthTokenCache.getIfPresent(authToken.toString());
            if (userInfo == null) {
                userInfo = fetchAndCacheUserInfo(authToken);
            }
            c.putAll(userInfo.claims());
            c.put(settings.getGroupsClaimName(), userInfo.groups());
            return userInfo.claims();
        } else {
            Object groupsClaim = jwtClaims.getClaimValue(settings.getGroupsClaimName());
            Collection<String> roles = parseTokenClaims(groupsClaim);
            c.put(settings.getGroupsClaimName(), roles);
        }
        return c;
    }
    
    private Collection<String> parseTokenClaims(Object groupsClaim) {
        if (groupsClaim == null) {
            return Collections.emptyList();
        }
        if (groupsClaim instanceof String groupClaimString) {
            return List.of(groupClaimString);
        }
        if (groupsClaim instanceof Collection<?> groups) {
            if (groups.stream().allMatch(group -> group instanceof String)) {
                return (Collection<String>) groups;
            }
        }
        throw new IllegalArgumentException(String.format("JWT groups claim must be a string, or a list of strings, instead was '%s'", groupsClaim));
    }
 
    public String getName() {
        return "oidc-" + settings.getProviderName();
    }
    
    private UserInfo fetchAndCacheUserInfo(AuthToken authToken)
            throws IOException, InterruptedException, JoseException, AuthenticationException {
        
        HttpRequest request = HttpRequest.newBuilder(settings.getUserInfoUrl())
                .header("Authorization", "Bearer " + new String(authToken.credentials()))
                .header(ACCEPT, APPLICATION_JSON)
                .GET()
                .build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() == 200) {
            Map<String, Object> responsePayload = JsonUtil.parseJson(response.body());
            Collection<String> groups = parseTokenClaims(responsePayload.get(settings.getGroupsClaimName()));
            String username = JsonHelp.getString(responsePayload, settings.getUsernameClaimName());
            var userInfo = new UserInfo(username, groups, responsePayload);
            userInfoAuthTokenCache.put(authToken.toString(), userInfo);
            return userInfo;
        } else {
            throw new AuthenticationException(String.format(
                    "Identity provider returned HTTP status %d error when calling userinfo endpoint",
                    response.statusCode()));
        }
    }

    private record UserInfo(String token, Collection<String> groups, Map<String,Object> claims) {}
    
    private class TokenExpiryCheck implements ValidityCheck {

        private final NumericDate exp;
        private final long clockSkewSeconds;

        TokenExpiryCheck(NumericDate exp, long clockSkewSeconds) {
            this.clockSkewSeconds = clockSkewSeconds;
            this.exp = exp;
        }

        @Override
        public void validate() {
            var timeNow = NumericDate.now();
            timeNow.addSeconds(-clockSkewSeconds);
            if (timeNow.isAfter(exp)) {
                throw new AuthTokenExpiredException(MessageConstants.AUTHENTICATION_INFO_EXPIRED);
            }
        }
    }
}

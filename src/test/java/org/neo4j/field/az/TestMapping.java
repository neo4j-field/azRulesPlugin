package org.neo4j.field.az;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.neo4j.logging.Level;
import org.neo4j.logging.Log;
import org.neo4j.logging.log4j.Log4jLogProvider;


public class TestMapping {
    static Log4jLogProvider logProvider = new Log4jLogProvider(System.out);
    Log log = logProvider.getLog(TestMapping.class);
    
    @BeforeAll
    public static void setup() {
        logProvider.updateLogLevel(Level.DEBUG);
    }
    
    @Test
    public void testMapping1() throws Exception {
        
        log.info("Test Mapping 1");
        String token="eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJzWnZYREV5eHhPX3BlVnBzdHJwRkRRbVdvSHRWd2JoTlJS" +
"VUpreTRMLUNzIn0.eyJleHAiOjE3MjEwNTY5NjMsImlhdCI6MTcyMTA1NjY2MywiYXV0aF90aW1lIjoxNzIxMDU2NjYyLCJqdGkiOiI4N2VlNjNlOS03Mzg4LTQxMTctYjgwYS0wY2RmYzBhMDE5Y2IiLCJpc3MiOiJodHRwczovL2tleWNsb2FrOjg0NDMvcmVhbG1zL215LX" +
"JlYWxtIiwiYXVkIjoibmVvNGotc3NvIiwic3ViIjoiNDgwZmM5ZjMtNGU3Ny00NWQ3LTlkM2UtMWI1ZDQ2NWJiNTVhIiwidHlwIjoiSUQiLCJhenAiOiJuZW80ai1zc28iLCJzZXNzaW9uX3N0YXRlIjoiOGRiZjRmZTgtZDEyNy00NzUyLTgzMzgtOWQxMjBjYmFlZmIyIiwi" +
"YXRfaGFzaCI6IndTS1FXTlR6Zm9kWm1fRXA1YlNnVFEiLCJzaWQiOiI4ZGJmNGZlOC1kMTI3LTQ3NTItODMzOC05ZDEyMGNiYWVmYjIiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInJvbGVzIjpbImFuYWx5c3QiXSwibmFtZSI6IlRlc3QgQW5hbHlzdCIsInByZWZlcnJlZF" +
"91c2VybmFtZSI6ImFuYWx5c3QiLCJnaXZlbl9uYW1lIjoiVGVzdCIsImZhbWlseV9uYW1lIjoiQW5hbHlzdCIsImVtYWlsIjoiYW5hbHlzdCJ9.S_D_1ASULpcow_Syop9TI-thpRtetDN_FT-_YNLdC2Rqfg6MlRVkwwcJil2WjZf_reb5UhrVrON5YpkhLevkF94XIWvuMGB" +
"hQBvKFsL2Dz3kDRJ1PhrAMXjAuNY7dE5PsKsefRRw9iPphiLLGRllDluAR1PbbJyxWoKPsNvCORH6aVvqokTYS-52NBUS81cYTR0w0j4pEkDDnnmZyIz-By1jrQ1AF6C4s9mqb7CqpgRPGp23TphSGUn7Gt5RbnAyvVV64exvj7Sfq05xsJn8s-qG1D7ZzJUV57yAc73SAiwJ2" +
"PmaVx4wNL1kx2i_vIYsXnviy_RaDi4yv_zyMgHUoQ";
        
        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setDisableRequireSignature()
                .setSkipSignatureVerification()
                .setSkipAllValidators()
                .build();
        JwtClaims j = jwtConsumer.processToClaims(token);
        log.info("Claims:" + j);
        //j.setClaim("roles", Arrays.asList("ldaprole1","ldaprole2"));
        
        String mapping = "roles:ldaprole1&&roles:ldaprole5=role1;roles:ldaprole2=role2;roles:ldaprole3=role3";
        AzRulesGroupRoleMapping x = new AzRulesGroupRoleMapping(mapping, logProvider.getLog(getClass()));
        Collection<String> roles = x.get(j.getClaimsMap(null));
        log.info("RolesMapped: " + roles);
    }
    
    @Test
    public void testMapping2() {
        log.info("--------------");
        log.info("Test Mapping2");
        Map<String, Object>claims = new HashMap<>();
        claims.put("roles", Arrays.asList("ldaprole1","ldaprole2", "ldaprole5"));
        claims.put("empType", "staff");
        claims.put("clearance", Arrays.asList("TS", "SI"));

        String mapping = "roles:ldaprole1&&empType:staff&&clearance:TS&&clearance:SI=role1;roles:ldaprole2=role2;roles:ldaprole3=role3";
        AzRulesGroupRoleMapping m = new AzRulesGroupRoleMapping(mapping, logProvider.getLog(getClass()));
        List<AzRuleSet> x = m.getMapping();
        log.info("Mapping:" + x);
        Collection<String>roles = m.get(claims);
        log.info("RolesMapped:" + roles);
        assertTrue(roles.contains("role1"));
        assertTrue(roles.contains("role2"));
        assertFalse(roles.contains("role3"));
    }
    
//    @Test
//    public void testMapping3() {
//        System.out.println("--------------");
//        System.out.println("Test Mapping3");
//        Collection<String> testRoles = Arrays.asList("ldaprole1","ldaprole2", "ldaprole5");
//        Map<String, Object>claims = new HashMap<>();
//        claims.put("roles", Arrays.asList("ldaprole1","ldaprole2", "ldaprole5"));
//        claims.put("empType", "staff");
//        claims.put("clearance", Arrays.asList("TS", "SI"));
//        String mapping = "roles:ldaprole1&&roles:ldaprole5=role1;roles:ldaprole2=role2;roles:ldaprole3=role3";
//        AzRulesGroupRoleMapping m = new AzRulesGroupRoleMapping(mapping, logProvider.getLog(getClass()));
//        Collection<String> roles = m.get(testRoles);
//        System.out.println("rolesmapped:" + roles);
//    }
    
    @Test
    public void testMapping4() {
        log.info("--------------");
        log.info("Test Mapping4 - cn");
        Map<String, Object>claims = new HashMap<>();
        claims.put("roles", Arrays.asList("ldaprole1","ldaprole2", "ldaprole5", "cn=group1, ou=groups, o=U.S. Government, c=US"));
        claims.put("empType", "staff");
        claims.put("clearance", Arrays.asList("TS", "SI"));
        String mapping = "roles:\"cn=group1, ou=groups, o=U.S. Government, c=US\"&&roles:ldaprole5=role1;roles:ldaprole2=role2,role9;roles:ldaprole3=role3,role5";
        AzRulesGroupRoleMapping m = new AzRulesGroupRoleMapping(mapping, logProvider.getLog(getClass()));
        Collection<String> roles = m.get(claims);
        log.info("RolesMapped:" + roles);
        assertTrue(roles.contains("role1"));
        assertTrue(roles.contains("role2"));
        assertTrue(roles.contains("role9"));
    }
    
    @Test
    public void testMapping5() {
        log.info("--------------");
        log.info("Test Complex");
        Map<String, Object>claims = new HashMap<>();
        claims.put("roles", Arrays.asList("ldaprole1","ldaprole2", "ldaprole5"));
        claims.put("empType", "staff");
        claims.put("clearance", Arrays.asList("TS", "SI"));
        
        // test out simple AND mapping - false
        String mapping = "(roles:ldaprole4&&roles:ldaprole5)=role1,junk2";
        AzRulesGroupRoleMapping m1 = new AzRulesGroupRoleMapping(mapping, logProvider.getLog(getClass()));
        Collection<String>roles1 = m1.get(claims);
        assertEquals(0, roles1.size());
        
        // test out OR and AND - false
        mapping="((roles:ldaprole2&&roles:junk2)||(roles:ldaprole2&&roles:ldaprole10))=role2,role9";
        AzRulesGroupRoleMapping m2 = new AzRulesGroupRoleMapping(mapping, logProvider.getLog(getClass()));
        Collection<String>roles2 = m2.get(claims);
        assertEquals(0, roles2.size());
        
        // test out OR and AND - true
        mapping="((roles:ldaprole2&&roles:ldaprole5)||(roles:ldaprole2&&roles:ldaprole10))=role2,role9";
        AzRulesGroupRoleMapping m3 = new AzRulesGroupRoleMapping(mapping, logProvider.getLog(getClass()));
        Collection<String>roles3 = m3.get(claims);
        
        assertEquals(2, roles3.size());
        assertTrue(roles3.contains("role9"));
        assertTrue(roles3.contains("role2"));
        
        // test out other claims - true
        mapping = "(roles:ldaprole6&&roles:ldaprole5)||empType:staff=role3";
        AzRulesGroupRoleMapping m4 = new AzRulesGroupRoleMapping(mapping, logProvider.getLog(getClass()));
        Collection<String>roles4 = m4.get(claims);
        assertEquals(1, roles4.size());
        assertTrue(roles4.contains("role3"));
        
        // test out NOT operator - false
        mapping = "(roles:ldaprole6&&roles:ldaprole5)||!empType:staff=role3";
        log.debug("mapping:" + mapping);
        AzRulesGroupRoleMapping m5 = new AzRulesGroupRoleMapping(mapping, logProvider.getLog(getClass()));
        Collection<String>roles5 = m5.get(claims);
        assertEquals(0, roles5.size());
        
        // test out NOT operator - true
        mapping = "(roles:ldaprole6&&roles:ldaprole5)||!empType:contractor=role3";
        log.debug("mapping:" + mapping);
        AzRulesGroupRoleMapping m5a = new AzRulesGroupRoleMapping(mapping, logProvider.getLog(getClass()));
        Collection<String>roles5a = m5a.get(claims);
        assertEquals(1, roles5a.size());
        assertTrue(roles5a.contains("role3"));
        
        // test multiple - true, false, true
        mapping = "(roles:ldaprole1&&roles:ldaprole5)=role1,junk2;((roles:ldaprole2&&roles:junk2)||(roles:ldaprole3&&roles:ldaprole10))=role2,role9;empType:staff=role3,role5";
        AzRulesGroupRoleMapping m6 = new AzRulesGroupRoleMapping(mapping, logProvider.getLog(getClass()));
        Collection<String>roles6 = m6.get(claims);
        assertEquals(4, roles6.size());
        assertTrue(roles6.contains("role1"));
        assertTrue(roles6.contains("junk2"));
        assertTrue(roles6.contains("role3"));
        assertTrue(roles6.contains("role5"));
    }
    
    @Test
    public void testMapping6() {
        log.info("--------------");
        log.info("Test Complex with Groups");
        Map<String, Object>claims = new HashMap<>();
        claims.put("roles", Arrays.asList("ldaprole1","ldaprole2", "ldaprole5"));
        claims.put("empType", "staff");
        //claims.put("groups", Arrays.asList("cn=TestGroup1, ou=groups, o=U.S. Government,c=us", "cn=TestGroup2, ou=groups, o=U.S. Government,c=us"));
        claims.put("clearance", Arrays.asList("TS", "SI"));
        
        // test out simple AND mapping - false
        String mapping = "groups:\"cn=TestGroup1, ou=groups, o=U.S. Government,c=us\"=role5";
        AzRulesGroupRoleMapping m = new AzRulesGroupRoleMapping(mapping, logProvider.getLog(getClass()));
        Collection<String>roles = m.get(claims);
        assertEquals(0, roles.size());
        
        // add a claim making it true
        claims.put("groups", Arrays.asList("cn=TestGroup1, ou=groups, o=U.S. Government,c=us", "cn=TestGroup2, ou=groups, o=U.S. Government,c=us"));
        AzRulesGroupRoleMapping m2 = new AzRulesGroupRoleMapping(mapping, logProvider.getLog(getClass()));
        Collection<String>roles2 = m2.get(claims);
        assertEquals(1, roles2.size());
        assertTrue(roles2.contains("role5"));
        
        // NOT - making it false
        mapping = "!groups:\"cn=TestGroup1, ou=groups, o=U.S. Government,c=us\"=role5";
        AzRulesGroupRoleMapping m3 = new AzRulesGroupRoleMapping(mapping, logProvider.getLog(getClass()));
        Collection<String>roles3 = m3.get(claims);
        assertEquals(0, roles3.size());
    }
    
    @Test
    public void testMapping7() {
        log.info("--------------");
        log.info("Test Complex with Groups and Patterned Role Name");
        Map<String, Object>claims = new HashMap<>();
        claims.put("caveats", Arrays.asList("SI","TK", "G"));
        claims.put("citizenship", "US");
        //claims.put("groups", Arrays.asList("cn=TestGroup1, ou=groups, o=U.S. Government,c=us", "cn=TestGroup2, ou=groups, o=U.S. Government,c=us"));
        claims.put("clearance", Arrays.asList("TS"));
        
        // test out simple AND mapping - false
        String mapping = "(clearance:TS&&caveats:SI&&caveats:TK&&caveats:G&&(citizenship:US||citizenship:UK||citzenship:NZ||citizenship:AUS||citizenship:CAN))=TS_SI__TK__G_FVEY,S_SI__TK__G_FVEY,TS,S,${clearance}_${caveats}_${citizenship}";
        AzRulesGroupRoleMapping m = new AzRulesGroupRoleMapping(mapping, logProvider.getLog(getClass()));
        Collection<String>roles = m.get(claims);
        log.info("roles::" + roles);
        //assertEquals(0, roles.size());
        
        
    }
}
package org.neo4j.field.az;

import static java.lang.String.format;
import com.neo4j.configuration.SecuritySettings;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.neo4j.logging.InternalLog;

/**
 * TODO - handle additional boolean operators
 */
public class AzRulesGroupRoleMapping {
    private static final String GROUP_DELIMITER = ";";
    private static final String CLAIM_DELIMITER = ":";
    private static final String KEY_VALUE_DELIMITER = "=";
    private static final String ROLE_DELIMITER = ",";
    private static final String AND_OPERATOR = "&&";
    private static final String OR_OPERATOR = "||";
    private static final String NEGATE_OPERATOR = "!";
    
    // Parser regex for group-to-role-mapping
    private static final String KEY_GROUP = "\\s*('(.+)'|\"(.+)\"|(\\S)|(\\S.*\\S))\\s*";
    private static final String VALUE_GROUP = "\\s*(.*)";
    private static final Pattern keyValuePattern = Pattern.compile(KEY_GROUP + KEY_VALUE_DELIMITER + VALUE_GROUP);
    
    //private static final Pattern complexPattern = Pattern.compile("^([^:]+):\"?([a-zA-Z0-9\\=\\, \\.&|!\\^]+)\"?=([A-Za-z0-9\\,]+)");
    private static final Pattern complexPattern = Pattern.compile("^([^:]+):\"?([a-z0-9A-Z=, \\.&:|!\\^\\(\\)]+)\"?");

    private final List<AzRuleSet> mappingRules;
    private InternalLog log;

    AzRulesGroupRoleMapping(String groupToRoleMappingString, InternalLog ilog) {
        ilog.debug("Parsing rule string: " + groupToRoleMappingString);
        mappingRules = parseComplexAzRulesMapping(groupToRoleMappingString, ilog);
        log = ilog;
    }

    /* simple azrules mapping - to be removed */
    public static List<AzRuleSet> parseAzRulesMapping(String groupMapping, InternalLog ilog) {
        Map<String, Collection<String>> map = new HashMap<>();
        List<AzRuleSet> rules = new ArrayList<>();
        if (groupMapping != null) {
            for (String groupAndRoles : groupMapping.split(GROUP_DELIMITER)) {
                if (!groupAndRoles.isEmpty()) {               
                    rules.add(parseRuleSet(groupAndRoles, ilog));
                }       
            }
        } 
        ilog.debug("Parsed rulesets:" + rules);
        return rules;
    }
    
    public List<AzRuleSet> parseComplexAzRulesMapping(String groupMapping, InternalLog ilog) {
        Map<String, Collection<String>> map = new HashMap<>();
        List<AzRuleSet> rules = new ArrayList<>();
        if (groupMapping != null) {
            for (String groupAndRoles : groupMapping.split(GROUP_DELIMITER)) {
                ilog.debug("Parse GroupsandRoles:" + groupAndRoles);
                if (!groupAndRoles.isEmpty()) {           
                    ilog.debug("Groups: " + groupAndRoles);
                    rules.add(parseComplexRuleSet(groupAndRoles, ilog));
                }       
            }
        } 
        return rules;
    }
    
    public List<AzRuleSet> getMapping() {
        return mappingRules;
    }
    
    /* basic parsing - to be removed */
    private static AzRuleSet parseRuleSet(String input, InternalLog ilog) {
        String z[] = input.split(KEY_VALUE_DELIMITER);
        AzRuleSet x = new AzRuleSet(z[1]);
        for (String rule: z[0].split(AND_OPERATOR) ) {
            ilog.debug("Rule:" + rule);
            x.addRule(rule);
        }
        return x;
    }
    
    private static AzRuleSet parseComplexRuleSet(String input, InternalLog ilog) {
        ilog.debug("Parse complex rule: " + input);
        int i = input.lastIndexOf(KEY_VALUE_DELIMITER); 
        String z[] =  {input.substring(0, i), input.substring(i+1)};
        ilog.debug("Complex: " + Arrays.asList(z));
        AzRuleSet x = new AzRuleSet(z[1], z[0]);
        for (String rule : z[0].split("&&|\\|\\||\\^")) {
            ilog.debug("rule: " + rule);
            String cr = rule.replaceAll("[\\(\\)\"\\!]", "");
            ilog.debug("Cleaned rule: " + cr);
            x.addRule(cr);
        }
        return x;       
    }
    
    // not used
    private static Map<String, Collection<String>> parseGroupToRoleMapping(
            String groupToRoleMappingString, InternalLog log) {
        Map<String, Collection<String>> map = new HashMap<>();

        if (groupToRoleMappingString != null) {
            for (String groupAndRoles : groupToRoleMappingString.split(GROUP_DELIMITER)) {
                if (!groupAndRoles.isEmpty()) {
                    Matcher matcher = keyValuePattern.matcher(groupAndRoles);
                    if (!(matcher.find() && matcher.groupCount() == 6)) {
                        String errorMessage = format(
                                "Failed to parse setting %s: wrong number of fields",
                                SecuritySettings.ldap_authorization_group_to_role_mapping.name());
                        throw new IllegalArgumentException(errorMessage);
                    }

                    String group = matcher.group(2) != null
                            ? matcher.group(2)
                            : matcher.group(3) != null
                                    ? matcher.group(3)
                                    : matcher.group(4) != null
                                            ? matcher.group(4)
                                            : matcher.group(5) != null ? matcher.group(5) : "";

                    if (group.isEmpty()) {
                        String errorMessage = format(
                                "Failed to parse setting %s: empty group name",
                                SecuritySettings.ldap_authorization_group_to_role_mapping.name());
                        throw new IllegalArgumentException(errorMessage);
                    }
                    Collection<String> roleList = new ArrayList<>();
                    for (String role : matcher.group(6).trim().split(ROLE_DELIMITER)) {
                        if (!role.isEmpty()) {
                            roleList.add(role);
                        }
                    }
                    if (map.containsKey(group)) {
                        log.warn(
                                "Invalid group to role mapping. The group '%s' has been defined multiple times. Using the last value. This will prevent neo4j from starting in future versions."
                                        .formatted(group));
                    }
                    // We only support case-insensitive comparison of group DNs
                    map.put(group.toLowerCase(), roleList);
                }
            }
        }
        return map;
    }
    
    Collection<String> get(Map<String,Object> allClaims) {
        log.debug("getting mapped roles from: " + mappingRules + " using claims: " + allClaims);
        Set<String> mappedRoles = new HashSet<>();
        for (AzRuleSet z : mappingRules) {
            log.debug("Evaluate Rule: " + z + "->" + z.evaluateX(allClaims));
            if (z.evaluateX(allClaims)) {
                //mappedRoles.addAll(z.results);
                log.info("HERE:" + z.getEvaluatedResults(allClaims));
                mappedRoles.addAll(z.getEvaluatedResults(allClaims));
            }
        }
        return mappedRoles;
    }
}
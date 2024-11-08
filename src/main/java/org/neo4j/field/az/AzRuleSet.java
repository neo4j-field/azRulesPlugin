package org.neo4j.field.az;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import org.mvel2.MVEL;

/**
 * holds a set of rules that map to one or more neo4j roles.
 * rules are combined using boolean operators in a ruleset
 * @author garymann
 */
public class AzRuleSet {
    List<AzRule> rules = new ArrayList<>();
    List<String> results = new ArrayList<>();
    private String orig;
    private String processed;
    
    public AzRuleSet(){};
    
    public AzRuleSet(String res) {
        results.addAll(Arrays.asList(res.split(",")));
    }
    
    // pass in the original string
    public AzRuleSet(String res, String o) {
        results.addAll(Arrays.asList(res.split(",")));
        orig = o;
    }
    
    public AzRuleSet(List<AzRule> list) {
        rules.addAll(list);
    }
    
    public void addRule(AzRule z) {
        rules.add(z);
    }
    
    public void addRule(String rulestr) {
        String[] r = rulestr.split(":");
        rules.add(new AzRule(r[0],r[1]));
    }
    
    public List<AzRule> getRules() {
        return rules;
    }
    
    public String getProcessed() {
        return processed;
    }
    
    // handle quotes.
    private String processRuleString() {
        String z = orig;
        int i = 0;
        for (AzRule r : rules) {
            z = z.replace(r.toString().replace(":", ":\"") + "\"" , "{" + i + "}");                 
            z = z.replace(r.toString(), "{" + i++ + "}");
        }
        processed = z;
        return z;
    }
    
    /**
     * evaluate against claims - supports boolean operators &&, ||, ^, and !.
     */
    public boolean evaluateX(Map<String, Object> claims) {
        processRuleString();
        String ev = processed;
        int i = 0;
        for (AzRule rule : rules) {
            if (!claims.isEmpty()) {
                Object o = claims.get(rule.claim());
                if (o == null) {
                    ev = ev.replace("{"+i++ +"}", String.valueOf(false));
                }
                else if (o instanceof String claimString) {
                    if (!rule.contents().equals(o)) {
                        ev = ev.replace("{"+i++ +"}", String.valueOf(false));
                    } else {
                        ev = ev.replace("{"+i++ +"}", String.valueOf(true));
                    }
                }
                else if (o instanceof Collection<?> coll) {
                    if (!coll.contains(rule.contents())) {
                        ev = ev.replace("{"+i++ +"}", String.valueOf(false));
                    } else {
                        ev = ev.replace("{"+i++ +"}", String.valueOf(true));
                    }
                }
                else { // some type that we don't understand
                    ev = ev.replace("{"+i++ +"}", String.valueOf(false));
                }
            }
        }
        Boolean b = (Boolean)MVEL.eval(ev);
        return b;
    }
    
    public List<String> getEvaluatedResults(Map<String, Object> claims) {
        List<String> eval = new ArrayList<>();
        for (String r : results) {
            if (r.contains("${")) {
                String e = r;
                for (Map.Entry<String, Object> rep : claims.entrySet()) {
                    Object o = rep.getValue();
                    if (o instanceof String) {
                        e = e.replace("${" + rep.getKey() + "}", (String)o);
                    } else if (o instanceof Collection<?>) {
                        String x = String.join("__", (List<String>) o);
                        e = e.replace("${" + rep.getKey() + "}", x);
                    }
                }
                eval.add(e);
            } else {
                eval.add(r);
            }
        }
        return eval;
    }
    
    @Override
    public String toString() {
        return "{" + rules.toString() + "==>" + results.toString() + "}";
    }
    
    private record AzRule(String claim, String contents) {
        @Override
        public String toString() {
            return claim + ":" + contents;
        }
    } 
}
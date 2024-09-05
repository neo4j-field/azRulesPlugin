package org.neo4j.field.az;

import org.neo4j.annotations.service.ServiceProvider;
import org.neo4j.configuration.Description;
import org.neo4j.configuration.SettingsDeclaration;
import org.neo4j.graphdb.config.Setting;
import static org.neo4j.configuration.SettingImpl.newBuilder;
import static org.neo4j.configuration.SettingValueParsers.BOOL;

@ServiceProvider
public class AzRulesSettings implements SettingsDeclaration {
    
    @Description("Flag to enable/disable adding IDP roles/groups to Neo4j roles/groups list")
    public static final Setting<Boolean> add_idp_roles_groups =
            newBuilder( "dbms.security.azrules.add_idp_roles_groups", BOOL, true ).build();
}

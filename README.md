# Authorization Rules Plugin

Plugin/Extension to implement some rules around mapping claims from an IDP to Neo4j roles.

## Install

* put azRulesPlugin-x.x.x-deploy.jar into NEO4J_HOME/plugins directory
* edit neo4j.conf to specify properties that we pull as part of the db (early) startup process

        dbms.security.authentication_providers=plugin-org.neo4j.field.az.AzRulesAzPlugin,native
        dbms.security.authorization_providers=plugin-org.neo4j.field.az.AzRulesAzPlugin,native
        dbms.security.ldap.authorization.group_to_role_mapping=<see Mapping Configuration below>

* optionally use this setting to disable default behavior of adding all roles/groups from idp to neo4j

        dbms.security.azrules.add_idp_roles_groups=false

* optionally use this setting to disable requiring iat claim in a token.  use this only for access tokens if needed.

        dbms.security.azrules.require_iat_claim=false

* restart neo4j

## Mapping Configuration

The mapping parameter is a boolean string using &&, ||, ^, and ! operators.  The mapping rules are all in the form of:

         <claim name>:<required contents>

Rules are separated by semi-colons.

An example is:

         (roles:role1&&roles:role5)=admin;empType:staff=staffrole 

which says:

* if the user has role1 and role5, grant them admin role in neo4j.  
* if the user has a staff empType claim, grant them staffrole in Neo4j

## Limitations & More Info

* Tested for use with SSO oidc provider.  Could be exstended/tested to use with custom auth tokens as well.




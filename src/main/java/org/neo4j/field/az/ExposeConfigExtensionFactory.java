package org.neo4j.field.az;

import org.neo4j.annotations.service.ServiceProvider;
import org.neo4j.bolt.tx.Transaction;
import org.neo4j.configuration.Config;
import org.neo4j.dbms.api.DatabaseManagementService;
import org.neo4j.graphdb.GraphDatabaseService;
import org.neo4j.kernel.database.NamedDatabaseId;
import org.neo4j.kernel.extension.ExtensionFactory;
import org.neo4j.kernel.extension.ExtensionType;
import org.neo4j.kernel.extension.context.ExtensionContext;
import org.neo4j.kernel.internal.GraphDatabaseAPI;
import org.neo4j.kernel.lifecycle.Lifecycle;
import org.neo4j.kernel.lifecycle.LifecycleAdapter;
import org.neo4j.logging.internal.LogService;

@ServiceProvider
public class ExposeConfigExtensionFactory extends ExtensionFactory<ExposeConfigExtensionFactory.Dependencies> {

    public ExposeConfigExtensionFactory() {
        super(ExtensionType.DATABASE, "AzRulesStartup");
    }

    public static Config config = null;
    public static LogService logsvc = null;
    public static DatabaseManagementService dbms = null;
    public static GraphDatabaseAPI db = null;
    public static GraphDatabaseService dbs = null;

    @Override
    public Lifecycle newInstance(ExtensionContext context, Dependencies dependencies) {
        if (dependencies.graphdatabaseService().databaseName().equals(NamedDatabaseId.SYSTEM_DATABASE_NAME)) {
            return new LifecycleAdapter() {
                @Override
                public void init() {
                    config = dependencies.config();
                    logsvc = dependencies.logService();
                    dbms = dependencies.databaseManagementService();
                    db = dependencies.graphdatabaseAPI();
                    dbs = dependencies.graphdatabaseService();
                }

            };
        }
        return new LifecycleAdapter();
    }

    public interface Dependencies {
        Config config();
        LogService logService();
        DatabaseManagementService databaseManagementService();
        GraphDatabaseAPI graphdatabaseAPI();
        GraphDatabaseService graphdatabaseService();
    }
}
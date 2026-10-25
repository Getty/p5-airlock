package AirlockExample::Schema;

# DBIO schema for the Airlock table. Used by AirlockExample::StoreDBIO.

use DBIO 'Schema', -sqlite;

__PACKAGE__->load_namespaces;

1;

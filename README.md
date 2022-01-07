[comment]: # "Auto-generated SOAR connector documentation"
# RedLock

Publisher: Phantom  
Connector Version: 1\.0\.4  
Product Vendor: RedLock  
Product Name: RedLock  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 3\.0\.284  

This app integrates with RedLock and ingests new alerts

### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a RedLock asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**username** |  required  | string | Username
**password** |  required  | password | Password
**ingest\_days\_back** |  optional  | numeric | Start ingesting alerts from this many days ago

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[on poll](#action-on-poll) - Action handler for the ingest functionality  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'on poll'
Action handler for the ingest functionality

Type: **ingest**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**start\_time** |  optional  | Parameter Ignored in this app | numeric | 
**end\_time** |  optional  | Parameter Ignored in this app | numeric | 
**container\_id** |  optional  | Parameter Ignored in this app | numeric | 
**container\_count** |  required  | Maximum number of alerts to ingest | numeric | 
**artifact\_count** |  optional  | Parameter Ignored in this app | numeric | 

#### Action Output
No Output
# A half-baked SDK for Azure in Go

This is a half-baked (ie. only provides what we needed) SDK for Azure in Go.

## Authentication

### Use an authentication file

This SDK also supports authentication with a JSON file containing credentials for the service principal. In the Azure CLI, you can create a service principal and its authentication file with this command:

``` bash
az ad sp create-for-rbac --sdk-auth > mycredentials.json
```

Save this file in a secure location on your system where your code can read it. Set an environment variable with the full path to the file:

``` bash
export AZURE_AUTH_LOCATION=/secure/location/mycredentials.json
```

``` powershell
$env:AZURE_AUTH_LOCATION= "/secure/location/mycredentials.json"
```

The file looks like this, in case you want to create it yourself:

``` json
{
    "clientId": "<your service principal client ID>",
    "clientSecret": "your service principal client secret",
    "subscriptionId": "<your Azure Subsription ID>",
    "tenantId": "<your tenant ID>",
    "activeDirectoryEndpointUrl": "https://login.microsoftonline.com",
    "resourceManagerEndpointUrl": "https://management.azure.com/",
    "activeDirectoryGraphResourceId": "https://graph.windows.net/",
    "sqlManagementEndpointUrl": "https://management.core.windows.net:8443/",
    "galleryEndpointUrl": "https://gallery.azure.com/",
    "managementEndpointUrl": "https://management.core.windows.net/"
}
```


## Log Analytics support

Log Analytics is supported through environment variables:
- `LOG_ANALYTICS_KEY`
- `LOG_ANALYTICS_ID`

You can also specify a file with these values and specify the path to it in the `LOG_ANALYTICS_AUTH_LOCATION`:

``` bash
export LOG_ANALYTICS_AUTH_LOCATION=/secure/location/loganalytics.json
```

``` powershell
$env:LOG_ANALYTICS_AUTH_LOCATION= "/secure/location/loganalytics.json"
```

The file should look like this:

``` json
{
    "workspaceID": "<YOUR_LOG_ANALYTICS_WORKSPACE_ID>",
    "workspaceKey": "<YOUR_LOG_ANALYTICS_WORKSPACE_KEY>"
}
```
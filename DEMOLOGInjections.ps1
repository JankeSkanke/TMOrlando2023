

##### >>>> PUT YOUR VALUES HERE <<<<<
# Information needed to authenticate to Azure Active Directory and obtain a bearer token
$tenantId = "e87630f5-66df-47f3-8747-84801dbf1be7"; #the tenant ID in which the Data Collection Endpoint resides
$appId = "f4a20c89-a92e-4f29-a979-39b307c31eea"; #the app ID created and granted permissions
$appSecret = "XSd8Q~NkdSz.WwIZpfo~TPS9XrRm5NIzWAUcpaRM"; #the secret created for the above app - never store your secrets in the source code
##### >>>> END <<<<<
$DcrImmutableId = "dcr-bcffe5bfa59a4725bb5f5cbd31b19af1"
$Table = "DemoLogTM01_CL"
$DceURI = "https://tm-dce-loginjection-g7k6.westeurope-1.ingest.monitor.azure.com"


## Obtain a bearer token used to authenticate against the data collection endpoint
$scope = [System.Web.HttpUtility]::UrlEncode("https://monitor.azure.com//.default")   
$body = "client_id=$appId&scope=$scope&client_secret=$appSecret&grant_type=client_credentials";
$headers = @{"Content-Type" = "application/x-www-form-urlencoded" };
$uri = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
$bearerToken = (Invoke-RestMethod -Uri $uri -Method "Post" -Body $body -Headers $headers).access_token


        $log_entry = @{
            # Define the structure of log entry, as it will be sent
            TimeGenerated = Get-Date ([datetime]::UtcNow) -Format O
            ComputerName = "Comp003"
            ComputerSystem = "Windows"
            ComputerType = "Desktop"
        }


        $body = $log_entry | ConvertTo-Json -AsArray;
        $headers = @{"Authorization" = "Bearer $bearerToken"; "Content-Type" = "application/json" };
        $uri = "$DceURI/dataCollectionRules/$DcrImmutableId/streams/Custom-$Table"+"?api-version=2021-11-01-preview";
        $uploadResponse = Invoke-RestMethod -Uri $uri -Method "Post" -Body $body -Headers $headers;

        # Let's see how the response looks
        Write-Output 9
        Write-Output "---------------------"

        $ResourceId = "/subscriptions/5c66beaa-b30e-4e94-9a51-649bc4f3b5e7/resourceGroups/rg-EXT-Monitoring/providers/Microsoft.Insights/dataCollectionRules/TM-DCR-loginjection01" # Resource ID of the DCR to edit
        $FilePath = "temp.dcr" # Store DCR content in this file
        $DCR = Invoke-AzRestMethod -Path ("$ResourceId"+"?api-version=2021-09-01-preview") -Method GET
        $DCR.Content | ConvertFrom-Json | ConvertTo-Json -Depth 20 | Out-File -FilePath $FilePath


        
        $ResourceId = "<ResourceId>" # Resource ID of the DCR to edit
        $FilePath = "<FilePath>" # Store DCR content in this file
        $DCRContent = Get-Content $FilePath -Raw 
        Invoke-AzRestMethod -Path ("$ResourceId"+"?api-version=2021-09-01-preview") -Method PUT -Payload $DCRContent



# Onboarding for Agent 
$TenantID = "e87630f5-66df-47f3-8747-84801dbf1be7"  #Your Tenant ID
$SubscriptionID = "5c66beaa-b30e-4e94-9a51-649bc4f3b5e7" #Your Subscription ID
$ResourceGroup = "rg-ext-monitoring" #Your ResourceGroup

Connect-AzAccount -Tenant $TenantID

#Select the subscription
Select-AzSubscription -SubscriptionId $SubscriptionID

#Grant Access to User at root scope "/"
$user = Get-AzADUser -UserPrincipalName (Get-AzContext).Account

New-AzRoleAssignment -Scope '/' -RoleDefinitionName 'Owner' -ObjectId $user.Id

#Create Auth Token
$auth = Get-AzAccessToken

$AuthenticationHeader = @{
    "Content-Type" = "application/json"
    "Authorization" = "Bearer " + $auth.Token
    }


#1. Assign ‘Monitored Object Contributor’ Role to the operator
$newguid = (New-Guid).Guid
$UserObjectID = $user.Id

$body = @"
{
            "properties": {
                "roleDefinitionId":"/providers/Microsoft.Authorization/roleDefinitions/56be40e24db14ccf93c37e44c597135b",
                "principalId": `"$UserObjectID`"
        }
}
"@

$requestURL = "https://management.azure.com/providers/microsoft.insights/providers/microsoft.authorization/roleassignments/$newguid`?api-version=2021-04-01-preview"


Invoke-RestMethod -Uri $requestURL -Headers $AuthenticationHeader -Method PUT -Body $body


##########################

#2. Create Monitored Object

# "location" property value under the "body" section should be the Azure region where the MO object would be stored. It should be the "same region" where you created the Data Collection Rule. This is the location of the region from where agent communications would happen.
$Location = "westeurope" #Use your own loacation
$requestURL = "https://management.azure.com/providers/Microsoft.Insights/monitoredObjects/$TenantID`?api-version=2021-09-01-preview"
$body = @"
{
    "properties":{
        "location":`"$Location`"
    }
}
"@

$Respond = Invoke-RestMethod -Uri $requestURL -Headers $AuthenticationHeader -Method PUT -Body $body -Verbose
$RespondID = $Respond.id

##########################

#3. Associate DCR to Monitored Object
#See reference documentation https://learn.microsoft.com/en-us/rest/api/monitor/data-collection-rule-associations/create?tabs=HTTP
$associationName = "assoc01" #You can define your custom associationname, must change the association name to a unique name, if you want to associate multiple DCR to monitored object
$DCRName = "dcr-WindowsClientOS" #Your Data collection rule name

$requestURL = "https://management.azure.com$RespondId/providers/microsoft.insights/datacollectionruleassociations/$associationName`?api-version=2021-09-01-preview"
$body = @"
        {
                "properties": {
                    "dataCollectionRuleId": "/subscriptions/$SubscriptionID/resourceGroups/$ResourceGroup/providers/Microsoft.Insights/dataCollectionRules/$DCRName"
                }
            }

"@

Invoke-RestMethod -Uri $requestURL -Headers $AuthenticationHeader -Method PUT -Body $body

#(Optional example). Associate another DCR to Monitored Object
#See reference documentation https://learn.microsoft.com/en-us/rest/api/monitor/data-collection-rule-associations/create?tabs=HTTP
$associationName = "assoc02" #You must change the association name to a unique name, if you want to associate multiple DCR to monitored object
$DCRName = "dcr-PAW-WindowsClientOS" #Your Data collection rule name

$requestURL = "https://management.azure.com$RespondId/providers/microsoft.insights/datacollectionruleassociations/$associationName`?api-version=2021-09-01-preview"
$body = @"
        {
            "properties": {
                "dataCollectionRuleId": "/subscriptions/$SubscriptionID/resourceGroups/$ResourceGroup/providers/Microsoft.Insights/dataCollectionRules/$DCRName"
            }
        }

"@

Invoke-RestMethod -Uri $requestURL -Headers $AuthenticationHeader -Method PUT -Body $body

#4. (Optional) Get all the associatation.
$requestURL = "https://management.azure.com$RespondId/providers/microsoft.insights/datacollectionruleassociations?api-version=2021-09-01-preview"
(Invoke-RestMethod -Uri $requestURL -Headers $AuthenticationHeader -Method get).value

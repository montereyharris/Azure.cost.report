Function Get-ProjectUsageReport{
[CMDletbinding()]
[OutputType([psobject])]
<#

.SYNOPSIS

Get-ProjectUsageReport uses Get-UsageAggregates and RateCard API to pull information on Azure Usage.


.DESCRIPTION

Get-UsageAggregates pulls the resources used in Azure of a Hourly or Daily. Invoke-RestMethod is used to engage the RateCard Rest API. Then it is processed.


.PARAMETER Daily

Switch to get the usage reported in the last day 


.PARAMETER Monthly

Switch to get the usage reported in the last month.


.PARAMETER AzureTenant 

FQDN of the Azure Tenant you will authenticate against. This should be the default directory of the Subscription you are checking.


.PARAMETER OfferID
The offerID of the rates you are getting from Azure. Offer IDs are available at https://azure.microsoft.com/en-us/support/legal/offer-details/.

.PARAMETER Currency 
Currency in which the resource rates need to be provided

.PARAMETER Locale
The culture in which the resource data needs to be localized

.PARAMETER Region
The 2 letter ISO code where the offer was purchased.


.EXAMPLE 

Get-ProjectUsageReport -monthly -IncludeUnNamedProjects -AzureTenant "azuremagenium.onmicrosoft.com" -OfferID "MS-AZR-0003P" -currency USD -locale "en-US" -Region US -subscriptionName $subscriptionName


.NOTES

This was designed to run with Azure Powershell 1.0.0. You must have the Azure PowerShell Installed for it to work

#>
Param(
    [Parameter(Mandatory=$true,ParameterSetName='Daily')]
    [Parameter(Mandatory=$false,ParameterSetName='NoRateCard')]
    [switch]$daily,
    [Parameter(Mandatory=$true,ParameterSetName='Month')]
    [Parameter(Mandatory=$false,ParameterSetName='NoRateCard')]
    [switch]$monthly,
    [Parameter(Mandatory=$true,ParameterSetName='Custom')]
    [Parameter(Mandatory=$false,ParameterSetName='NoRateCard')]
    [string]$start,
    [Parameter(Mandatory=$true,ParameterSetName='Custom')]
    [Parameter(Mandatory=$false,ParameterSetName='NoRateCard')]
    [string]$end,
    [switch]$IncludeUnNamedProjects,

    [Parameter(Mandatory=$true, ParameterSetName= 'NoRateCard')]
    [string]$AzureTenant,

    [Parameter(Mandatory=$true, ParameterSetName= 'NoRateCard')]
    [ValidateSet("MS-AZR-0003P","MS-AZR-0033P","MS-AZR-0041P","MS-AZR-0042P","MS-AZR-0043P","MS-AZR-0044P","MS-AZR-0023P","MS-AZR-0059P","MS-AZR-0060P","MS-AZR-0062P","MS-AZR-0063P","MS-AZR-0025P","MS-AZR-0064P","MS-AZR-0036P","MS-AZR-0070P-0089P","MS-AZR-0120P-0130P","MS-AZR-0111p","MS-AZR-0026P","MS-AZR-0144P","MS-AZR-0149P","MS-AZR-0029P","MS-AZR-0005P","MS-AZR-0010P","MS-AZR-0011P","MS-AZR-0012P","MS-AZR-0027P","MS-AZR-0028P","MS-AZR-0034P","MS-AZR-0037P","MS-AZR-0038P","MS-AZR-0039P","MS-AZR-0040P","MS-AZR-0035P","MS-AZR-0061P","MS-AZR-0090P")]
    [string]$OfferID,

    [Parameter(Mandatory=$true, ParameterSetName= 'NoRateCard')]
    [string]$currency,

    [Parameter(Mandatory=$true, ParameterSetName= 'NoRateCard')]
    [string]$locale,

    [Parameter(Mandatory=$true, ParameterSetName= 'NoRateCard')]
    [string]$Region,

    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true, ParameterSetName= 'NoRateCard')]
    [string]$subscriptionName,

    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true, ParameterSetName= 'NoRateCard')]
    [string]$subscriptionID,

    [Parameter(Mandatory=$false,ParameterSetName= 'NoRateCard')]
    [switch]$ResourceManager,

    [Parameter(Mandatory=$true,ParameterSetName='Daily')]
    [Parameter(Mandatory=$true,ParameterSetName='Month')]
    [Parameter(Mandatory=$true,ParameterSetName='Custom')]
    [object]$AzureRateCard
)


    If($daily.IsPresent -and !$start -and !$end){g
    $Start=Get-date ((Get-Date).AddDays(-2)) -format d
    $End=Get-Date -Format d
    }

    If($monthly.IsPresent -and !$start -and !$end){
    $Start=Get-date ((Get-Date).AddDays(-32)) -format d
    $End=Get-Date -Format d
    }

    If(!$ResourceManager -and !$AzureRateCard){
        If($subscriptionName){
        $meters=Get-AzureRateCard -AzureADTenant $AzureTenant -OfferID $OfferID -currency $currency -locale $locale -Region $Region -subscriptionName $subscriptionName}

        If($subscriptionID){
        $meters=Get-AzureRateCard -AzureADTenant $AzureTenant -OfferID $OfferID -currency $currency -locale $locale -Region $Region -subscriptionID $subscriptionID}
        }

    If($ResourceManager -and !$AzureRateCard){
        If($subscriptionName){
        $meters=Get-AzureRateCard -AzureADTenant $AzureTenant -OfferID $OfferID -currency $currency -locale $locale -Region $Region -subscriptionName $subscriptionName -Resourcemanager}

        If($subscriptionID){
        $meters=Get-AzureRateCard -AzureADTenant $AzureTenant -OfferID $OfferID -currency $currency -locale $locale -Region $Region -subscriptionID $subscriptionID -Resourcemanager}
        }

    If($AzureRateCard){$meters=$AzureRateCard}
    $usage=(Get-UsageAggregates -ReportedStartTime $Start -ReportedEndTime $end -showdetails $true).UsageAggregations
    $projects=$usage.properties.infofields.project| Sort-object | get-unique
    Write-Verbose -Message "Pulling info related to these Projects:$projects"
    
    Foreach($pro in $projects){

            $burn=$usage|where-object{$_.properties.infofields.project -eq "$pro"}
            $cat=$burn.properties.meterid |Sort-object| get-unique
            Write-Verbose -Message "$cat"


        Foreach($c in $cat){
                 
                 
                      $guid=[guid]$c
                      $ratecard=$meters|where-object{$_.meterid -eq $guid}
                      $set=$burn.properties | where-object{$_.meterid -eq $guid}
                      Write-Verbose -Message "$set"
                      $total=($set | measure-object -sum quantity).sum
                      If($ratecard.tieredrates -eq $false){$rate=$ratecard.meterrates.0}
                      if($ratecard.tieredrates -eq $true){$ts=$ratecard.tierset
                                                            foreach($t in $ts){
                                                            Clear-Variable "Tier$t" -ErrorAction SilentlyContinue
                                                            New-Variable -name "Tier$t" -Visibility Private -ErrorAction SilentlyContinue
                                                            Set-Variable "Tier$t" -Value $t  
                                                            $rate=$ratecard.meterrates.0
                                                            $aprate=(get-variable "Tier$t" -ValueOnly)
                                                            Write-Verbose "$aprate"
                                                            if($total-gt $aprate){$rate=$ratecard.MeterRates.$aprate}
                                                        
                                                                                }                     
                                                           }
                  
                  
                      $cost=$rate*$total
                      $prop=[ordered]@{
                            
                                Project=$pro    
                                MeterId=$guid
                                Metername=$ratecard.MeterName
                                MeterSubCategory=$ratecard.MeterSubCategory
                                Currency=$ratecard.Currency 
                                Rates=$ratecard.meterrates
                                Unit=$ratecard.unit
                                Usage=$total 
                                AppliedRate=$rate 
                                Totalcost=$cost
                                                       
                                         }
                                New-Object PSObject -Property $prop 
                                    
                        } 
                                }

    If($IncludeUnNamedProjects){

           
              $blankusage=$usage
              Foreach($p in $projects){$blankusage=$blankusage|where-object{$_.Properties.InfoFields.Project -notlike "$P"}}
              $bat=$blankusage.properties.meterid |Sort-object| get-unique

              Foreach($c in $bat){
                 
                 
                      $guid=[guid]$c
                      $ratecard=$meters|where-object{$_.meterid -eq $guid}
                      $set=$blankusage.properties | where-object{$_.meterid -eq $guid}
                      Write-Verbose -Message "$set"
                      $total=($set | measure-object -sum quantity).sum
                      If($ratecard.tieredrates -eq $false){$rate=$ratecard.meterrates.0}
                      if($ratecard.tieredrates -eq $true){$ts=$ratecard.tierset
                                                            foreach($t in $ts){
                                                            Clear-Variable "Tier$t" -ErrorAction SilentlyContinue
                                                            New-Variable -name "Tier$t" -Visibility Private -ErrorAction SilentlyContinue
                                                            Set-Variable "Tier$t" -Value $t  
                                                            $rate=$ratecard.meterrates.0
                                                            $aprate=(get-variable "Tier$t" -ValueOnly)
                                                            Write-Verbose "$aprate"
                                                            if($total-gt $aprate){$rate=$ratecard.MeterRates.$aprate}
                                                        
                                                                                }                     
                                                           }
                  
                  
                      $cost=$rate*$total
                      $prop=[ordered]@{
                            
                                Project=""    
                                MeterId=$guid
                                Metername=$ratecard.MeterName
                                MeterSubCategory=$ratecard.MeterSubCategory
                                Currency=$ratecard.Currency 
                                Rates=$ratecard.meterrates
                                Unit=$ratecard.unit
                                Usage=$total 
                                AppliedRate=$rate 
                                Totalcost=$cost
                                                       
                                         }
                                New-Object PSObject -Property $prop 
                                    
                        }

            




    }
                            }

Function Get-AzureRateCard{

<#

.SYNOPSIS

Get-AzureRateCard uses RateCard API to pull information on Azure costs.


.DESCRIPTION

Invoke-RestMethod is used to engage the RateCard Rest API. Then it is processed.




.PARAMETER AzureADTenant 

FQDN of the Azure Tenant you will authenticate against. This should be the default directory of the Subscription you are checking.


.PARAMETER OfferID
The offerID of the rates you are getting from Azure. Offer IDs are available at https://azure.microsoft.com/en-us/support/legal/offer-details/.

.PARAMETER Currency 
Currency in which the resource rates need to be provided

.PARAMETER Locale
The culture in which the resource data needs to be localized

.PARAMETER Region
The 2 letter ISO code where the offer was purchased.


.EXAMPLE 

Get-AzureRateCard -AzureTenant "azure.onmicrosoft.com" -OfferID "MS-AZR-0003P" -currency USD -locale "en-US" -Region US -subscriptionName $subscriptionName


.NOTES

This was designed to run with Azure Powershell 1.0. You must have the Azure PowerShell Installed for it to work and ADAL libray in these locations ${env:ProgramFiles(x86)}\Microsoft SDKs\Azure\PowerShell\ServiceManagement\Azure\

#>

[cmdletbinding()]
[OutputType([psobject])]

    Param([Parameter(Mandatory=$true)]
          [string]$AzureADTenant,

          [Parameter(Mandatory=$true)]
          [ValidateSet("MS-AZR-0003P","MS-AZR-0033P","MS-AZR-0041P","MS-AZR-0042P","MS-AZR-0043P","MS-AZR-0044P","MS-AZR-0023P","MS-AZR-0059P","MS-AZR-0060P","MS-AZR-0062P","MS-AZR-0063P","MS-AZR-0025P","MS-AZR-0064P","MS-AZR-0036P","MS-AZR-0070P-0089P","MS-AZR-0120P-0130P","MS-AZR-0111p","MS-AZR-0026P","MS-AZR-0144P","MS-AZR-0149P","MS-AZR-0029P","MS-AZR-0005P","MS-AZR-0010P","MS-AZR-0011P","MS-AZR-0012P","MS-AZR-0027P","MS-AZR-0028P","MS-AZR-0034P","MS-AZR-0037P","MS-AZR-0038P","MS-AZR-0039P","MS-AZR-0040P","MS-AZR-0035P","MS-AZR-0061P","MS-AZR-0090P")]
          [string]$OfferID,

          [Parameter(Mandatory=$true)]
          [string]$currency,

          [Parameter(Mandatory=$true)]
          [string]$locale,

          [Parameter(Mandatory=$true)]
          [string]$Region,

          [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true, ParameterSetName='SubscriptionName')]
          [string]$subscriptionName,

          [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true,ParameterSetName='SubscriptionID')]
          [string]$subscriptionID,

          [Parameter(Mandatory=$false)]
          [Switch]$Resourcemanager,

          [Parameter(Mandatory = $false)]
          [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationResult]$ADALAuthResult

)

    If(!$Resourcemanager -and !$ADALAuthResult){
    If($SubscriptionID){Select-AzureSubscription -SubscriptionId $SubscriptionID}

    If($SubscriptionName){Select-AzureSubscription -SubscriptionName "$SubscriptionName"}
    }

    If($Resourcemanager -and !$ADALAuthResult){
    If($SubscriptionID){Set-AzureRmContext -SubscriptionId $SubscriptionID}

    If($SubscriptionName){Set-AzureRmContext -SubscriptionName "$SubscriptionName"}
    }

    If(!$ADALAuthresult -or $ADALAuthresult.GetType().fullname -ne "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationResult"){


# Set Azure AD Tenant name
       Write-Debug -Message "$AzureADTenant" 
# Set well-known client ID for AzurePowerShell
        $clientId = "1950a258-227b-4e31-a9cf-717495945fc2" 
# Set redirect URI for Azure PowerShell
        $redirectUri = "urn:ietf:wg:oauth:2.0:oob"
# Set Resource URI to Azure Service Management API
        $resourceAppIdURI = "https://management.core.windows.net/"
# Set Authority to Azure AD Tenant
        $authority = "https://login.windows.net/$AzureADTenant"
# Create Authentication Context tied to Azure AD Tenant
        $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority
# Acquire token
        $authResult = $authContext.AcquireToken($resourceAppIdURI, $clientId, $redirectUri, "Auto")
        $authHeader = $authResult.CreateAuthorizationHeader()
    }

    $apiVersion = "api-version=2015-06-01-preview"
# API method
    $method = "GET"
# authheader
    If($ADALAuthresult){$authHeader = $ADALAuthresult.CreateAuthorizationHeader()}
# Set HTTP request headers to include Authorization header
    $headers = @{"Authorization" = $authHeader}
# generate the API URI
    If(!$Resourcemanager -and $subscriptionName){ 

        $sub = (Get-AzureSubscription -Current -ExtendedDetails)
        $subID = $sub.SubscriptionID

                        }
    If($Resourcemanager -and $subscriptionName){ 
      
        $subID = (Get-AzureRmContext).Subscription.SubscriptionId
                    }
    If(!$subid -and $subscriptionID){$subid=$subscriptionID}

    $filter ="`$filter=OfferDurableId eq '$offerID' and Currency eq '$currency' and Locale eq '$locale' and RegionInfo eq '$Region'"
    $URI = "https://management.azure.com/subscriptions/$subID/providers/Microsoft.Commerce/RateCard?$apiversion&$filter"
    $contentType = "application/json;charset=utf-8"
# execute the Azure REST API
    $list = Invoke-RestMethod -Uri $URI -Method $method -Headers $headers -ContentType $contentType
    
   Clear-Variable $authContext
    
    $meters=$list.meters

    Foreach($meter in $meters)
                          {
                          $tiers = (($meter.MeterRates | Get-Member -MemberType NoteProperty).name).count
                          $tierRates = ($meter.MeterRates | Get-Member -MemberType NoteProperty).name | where-object{$_ -ne "0"}

                      if($tiers -gt 1){
                                            
                            $Prop=[ordered]@{
                                             MeterID = $meter.MeterID
                                             MeterName = $meter.MeterName
                                             Metercategory = $meter.Metercategory
                                             MeterSubCategory  =$meter.MeterSubCategory
                                             Unit = $meter.Unit
                                             MeterTags = $meter.MeterTags
                                             MeterRates = $meter.MeterRates
                                             EffectiveDate = $meter.EffectiveDate
                                             IncludedQuantity = $meter.IncludedQuantity
                                             IsTaxIncluded = $list.IsTaxIncluded
                                             Currency = $list.Currency
                                             Locale = $list.Locale
                                             OfferTerms = $list.OfferTerms
                                             TieredRates = ($true)
                                             TierSet = $tierRates 
                                        
                                             Tier0 = $meter.MeterRates.0

                                             }
                                             }
                      elseif($tiers -eq 1){                           
                          $Prop=[ordered]@{ 
                            
                                             MeterID = $meter.MeterID
                                             MeterName = $meter.MeterName
                                             Metercategory = $meter.Metercategory
                                             MeterSubCategory = $meter.MeterSubCategory
                                             Unit = $meter.Unit
                                             MeterTags = $meter.MeterTags
                                             MeterRates = $meter.MeterRates
                                             EffectiveDate = $meter.EffectiveDate
                                             IncludedQuantity = $meter.IncludedQuantity
                                             IsTaxIncluded = $list.IsTaxIncluded
                                             Currency = $list.Currency
                                             Locale = $list.Locale
                                             OfferTerms = $list.OfferTerms
                                             TieredRates = $false

                                             }
                        
                                             }
                                              New-Object PSObject -Property $prop
                         } 
                         } 

Function Get-ADALAccessResultContext
{

<#
 .SYNOPSIS
 Acquires OAuth 2.0 ADALAccessResultContext from Azure Active Directory (AAD)

 .DESCRIPTION
 The Get-ADALAccessResultContext cmdlet lets you acquire OAuth 2.0 AccessTokeADALAccessResultContext  from Azure Active Directory (AAD) 
 by using Active Directory Authentication Library (ADAL).

 There are two ways to get AccessToken
 
 1. You can pass UserName and Password to avoid SignIn Prompt.
 2. You can pass RedirectUri to use SignIn prompt.

 If you want to use different credential by using SignIn Prompt, use ForcePromptSignIn.
 Use Get-Help Get-AccessToken -Examples for more detail.

 .PARAMETER AuthorityName
 Azure Active Directory Name or Guid. i.e.)contoso.onmicrosoft.com

 .PARAMETER ClientId
 A registerered ClientId as application to the Azure Active Directory.

 .PARAMETER ResourceId
 A Id of service (resource) to consume.

 .PARAMETER UserName
 A username to login to Azure Active Directory.

 .PARAMETER Password
 A password for UserName

 .PARAMETER RedirectUri
 A registered RedirectUri as application to the Azure Active Directory.

 .PARAMETER ForcePromptSignIn
 Indicate to force prompting for signin in.

 .EXAMPLE
 Get-ADALAccessToken -AuthorityName contoso.onmicrosoft.com -ClientId 8f710b23-d3ea-4dd3-8a0e-c5958a6bc16d -ResourceId https://analysis.windows.net/powerbi/api -RedirectUri $redirectUri

 This example acquire accesstoken by using RedirectUri from contoso.onmicrosoft.com Azure Active Directory for PowerBI service. 
 It will only prompt you to sign in for the first time, or when cache is expired.

 .EXAMPLE
 Get-ADALAccessToken -AuthorityName contoso.onmicrosoft.com -ClientId 8f710b23-d3ea-4dd3-8a0e-c5958a6bc16d -ResourceId https://analysis.windows.net/powerbi/api -RedirectUri $redirectUri -ForcePromptSignIn

 This example acquire accesstoken by using RedirectUri from contoso.onmicrosoft.com Azure Active Directory for PowerBI service.
 It always prompt you to sign in.

  .EXAMPLE
 Get-ADALAccessToken -AuthorityName contoso.onmicrosoft.com -ClientId 8f710b23-d3ea-4dd3-8a0e-c5958a6bc16d -ResourceId https://analysis.windows.net/powerbi/api -UserName user1@contoso.onmicrosoft.com -Password password

 This example acquire accesstoken by using UserName/Password from contoso.onmicrosoft.com Azure Active Directory for PowerBI service. 

#>
    param
    (
        [parameter(Mandatory=$true)]
        [string]$AuthorityName,
        [parameter(Mandatory=$true)]
        [string]$ClientId,
        [parameter(Mandatory=$true)]
        [string]$ResourceId,
        [parameter(Mandatory=$true, ParameterSetName="credential")]
        [pscredential]
        [System.Management.Automation.Credential()] $credential,
        [parameter(Mandatory=$true, ParameterSetName="RedirectUri")]
        [string]$RedirectUri,
        [parameter(Mandatory=$false, ParameterSetName="RedirectUri")]
        [switch]$ForcePromptSignIn
    )    
    
    # Authority Format
    $authority = "https://login.windows.net/{0}/" -F $AuthorityName;
    # Create AuthenticationContext
    $authContext = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext($authority)
    
    try
    {
        if($RedirectUri -ne '')
        {
            # Create RedirectUri
            $rUri = New-Object System.Uri -ArgumentList $RedirectUri
            # Set PromptBehavior
            if($ForcePromptSignIn)
            {
                $promptBehavior = [Microsoft.IdentityModel.Clients.ActiveDirectory.PromptBehavior]::Always
            }
            else
            {
                $promptBehavior = [Microsoft.IdentityModel.Clients.ActiveDirectory.PromptBehavior]::Auto
            }
            # Get AccessToken
            $authResult = $authContext.AcquireToken($ResourceId, $ClientId, $rUri,$promptBehavior)
        }
        else
        {
            # Create Credential
            $cred = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.UserCredential($credential.UserName, $credential.Password)
            # Get AccessToken
            $authResult = $authContext.AcquireToken($ResourceId, $ClientId, $cred)
        }
    }
    catch [Microsoft.IdentityModel.Clients.ActiveDirectory.AdalException]
    {
        Write-Error $_
    }
    return $authResult
}

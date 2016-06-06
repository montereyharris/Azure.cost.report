# Azure.cost.report
Azure Cost Report module for PowerShell

# Overview
This is a PowerShell Module wrapper for RateCard API and Billing API in Azure. The Billing API is exposed via Get-UsageAggreagates with Azure PowerShell 1.0 and above. 
  
  I used Azure Aactive Dirtectory Libraries from this project: https://github.com/AzureAD/azure-activedirectory-library-for-dotnet for auth. I modified code from kenakamu's project Microsoft.ADAL.PowerShell project here https://github.com/kenakamu/Microsoft.ADAL.PowerShell to create ADAL Access Result Context. 

To install this you have two options: 
#git
    git clone https://github.com/montereyharris/Azure.cost.report.git %USERPROFILE%\Documents\WindowsPowerShell\Modules\Azure.Cost.Report

    git clone https://github.com/montereyharris/Azure.cost.report.git %WINDIR%\System32\WindowsPowerShell\v1.0\ModulesAzure.Cost.Report

#GUI
Download zip folder and unzip contents to %USERPROFILE%\Documents\WindowsPowerShell\Modules\Azure.Cost.Report or %WINDIR%\System32\WindowsPowerShell\v1.0\ModulesAzure.Cost.Report

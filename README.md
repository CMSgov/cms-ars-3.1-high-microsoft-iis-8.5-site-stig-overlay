# cms-ars-3.1-high-microsoft-iis-8.5-site-stig-overlay
InSpec profile overlay to validate the secure configuration of Microsoft IIS 8.5 Site against [DISA's](https://iase.disa.mil/stigs/Pages/index.aspx) Microsoft IIS 8.5 Site STIG Version 1 Release 6 tailored for [CMS ARS 3.1](https://www.cms.gov/Research-Statistics-Data-and-Systems/CMS-Information-Technology/InformationSecurity/Info-Security-Library-Items/ARS-31-Publication.html) for CMS systems categorized as High.

## Getting Started  
It is intended and recommended that InSpec and this profile overlay be run from a __"runner"__ host (such as a DevOps orchestration server, an administrative management system, or a developer's workstation/laptop) against the target remotely over __winrm__.

__For the best security of the runner, always install on the runner the _latest version_ of InSpec and supporting Ruby language components.__ 

Latest versions and installation options are available at the [InSpec](http://inspec.io/) site.

The following attributes must be configured in an attributes file for the profile to run correctly. More information about InSpec attributes can be found in the [InSpec Profile Documentation](https://www.inspec.io/docs/reference/profiles/).

```
# description: 'Specify if the server being reviewed is a public IIS 8.5 web server'
public_server: false

# description: 'Specify if the server being reviewed is a private IIS 8.5 web server'
private_server: false

# description: 'Specify if the server being reviewed is a non-production website'
non_production_server: false

# description: 'List of Request Filtering black listed extensions'
black_listed_extensions: []

# description: 'Name of IIS site'
site_name: ['tt', 'Default']

# description: 'IP address used for http'
http_ip: ['10.0.2.15', '0.0.0.0']

# description: 'IP address used for https'
http_hostname: ['local', 'l'] 
    
# description: 'IP address used for https'
https_ip: ['10.0.2.15', '0.0.0.0']

# description: 'Hostname used for https'
https_hostname: ['localhttps', 'localhttps2']

# description: 'Path of IIS log directory'
log_directory: 'C:\inetpub\logs\LogFiles'
```

## Running This Overlay
When the __"runner"__ host uses this profile overlay for the first time, follow these steps: 

```
mkdir profiles
cd profiles
git clone https://github.cms.gov/ispg/cms-ars-3.1-high-microsoft-iis-8.5-site-stig-overlay.git
git clone https://github.com/mitre/microsoft-iis-8.5-site-stig-baseline.git
cd cms-ars-3.1-high-microsoft-iis-8.5-site-stig-overlay
bundle install
cd ..
inspec exec cms-ars-3.1-high-microsoft-iis-8.5-site-stig-overlay --attrs=<path_to_your_attributes_file/name_of_your_attributes_file.yml> --target=winrm://<your_target_host_name_or_ip_address> --user=<target_account_with_administrative_privileges> --password=<password_for_target_account> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json> 
```

For every successive run, follow these steps to always have the latest version of this overlay and dependent profiles:

```
cd profiles/microsoft-iis-8.5-site-stig-baseline
git pull
cd ../cms-ars-3.1-high-microsoft-iis-8.5-site-stig-overlay
git pull
bundle install
cd ..
inspec exec cms-ars-3.1-high-microsoft-iis-8.5-site-stig-overlay --attrs=<path_to_your_attributes_file/name_of_your_attributes_file.yml> --target=winrm://<your_target_host_name_or_ip_address> --user=<target_account_with_administrative_privileges> --password=<password_for_target_account> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json> 
```

## Viewing the JSON Results

The JSON results output file can be loaded into __[heimdall-lite](https://mitre.github.io/heimdall-lite/)__ for a user-interactive, graphical view of the InSpec results. 

The JSON InSpec results file may also be loaded into a __[full heimdall server](https://github.com/mitre/heimdall)__, allowing for additional functionality such as to store and compare multiple profile runs.

## Authors
* Eugene Aronne
* Danny Haynes

## Special Thanks
* Rony Xavier
* Alicia Sturtevant

## Getting Help
To report a bug or feature request, please open an [issue](https://github.cms.gov/ispg/cms-ars-3.1-high-microsoft-iis-8.5-site-stig-overlay/issues/new).

## License
This is licensed under the [Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0) license. 

### NOTICE  

This software was produced for the U. S. Government under Contract Number HHSM-500-2012-00008I, and is subject to Federal Acquisition Regulation Clause 52.227-14, Rights in Data-General.  

No other use other than that granted to the U. S. Government, or to those acting on behalf of the U. S. Government under that Clause is authorized without the express written permission of The MITRE Corporation.

For further information, please contact The MITRE Corporation, Contracts Management Office, 7515 Colshire Drive, McLean, VA  22102-7539, (703) 983-6000.

### NOTICE
DISA STIGs are published by DISA IASE, see: https://iase.disa.mil/Pages/privacy_policy.aspx

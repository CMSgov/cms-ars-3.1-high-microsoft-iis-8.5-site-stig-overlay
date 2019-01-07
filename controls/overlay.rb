# encoding: utf-8
include_controls 'microsoft-iis-8.5-site-stig-baseline' do
  control 'V-76773' do
    desc 'check', 'Access the IIS 8.5 IIS Manager.
    
    Click the IIS 8.5 server.

    Select "Configuration Editor" under the "Management" section.

    From the "Section:" drop-down list at the top of the configuration editor, 
    locate "system.applicationHost/sites".

    Expand "siteDefaults".
    Expand "limits".

    Review the results and verify the value is "1" for the "maxconnections" 
    parameter.

    If the maxconnections parameter is set a value other than "1", this 
    is a finding.'
    desc 'fix', 'Access the IIS 8.5 IIS Manager.

         Click the IIS 8.5 server.

         Select "Configuration Editor" under the "Management" section.

         From the "Section:" drop-down list at the top of the configuration 
         editor, locate "system.applicationHost/sites".

         Expand "siteDefaults".
         Expand "limits".

         Set the "maxconnections" parameter to "1".'
    describe 'IIS Configuration' do
      subject { json(command: 'Get-WebConfigurationProperty 
                -Filter system.applicationHost/sites -name * | 
                select -   expand siteDefaults | select -expand limits | 
                ConvertTo-Json ') }
      its('maxBandwidth') { should eq 1 }
    end
  end

  control 'V-76783' do
    desc 'Log files are a critical component to the successful management 
         of an IS used within the CMS. By generating log files with useful 
         information web administrators can leverage them in the event of a 
         disaster, malicious attack, or other site-specific needs.

         Ascertaining the correct order of the events that occurred is 
         important during forensic analysis. Events that appear harmless by 
         themselves might be flagged as a potential threat when properly viewed 
         in sequence. By also establishing the event date and time, an event 
         can be properly viewed with an enterprise tool to fully see a possible 
         threat in its entirety.

         Without sufficient information establishing when the log event occurred, 
         investigation into the cause of event is severely hindered. Log record 
         content that may be necessary to satisfy the requirement of this control 
         includes, but is not limited to, time stamps, source and destination IP 
         addresses, user/process identifiers, event descriptions, 
         application-specific events, success/fail indications, file names involved, 
         access control, or flow control rules invoked.

         Satisfies: SRG-APP-000092-WSR-000055, SRG-APP-000093-WSR-000053'
    tag "cci": ['CCI-001487']
    tag "nist": ['AU-3', 'Rev_4']
    desc 'caveat', 'AU-14 is not listed in ARS, but the ARS AU-3 clearly implies the
         need for these fields in event records. As a result, the associated NIST 
          control has been changed to AU-3.'
  end

  control 'V-76809' do
    desc 'A CMS private website must utilize PKI as an authentication mechanism for web 
         users. Information systems residing behind web servers requiring authorization 
         based on individual identity must use the identity provided by certificate-based 
         authentication to support access control decisions. Not using client certificates 
         allows an attacker unauthenticated access to private websites.

         Satisfies: SRG-APP-000172-WSR-000104, SRG-APP-000224-WSR-000135, SRG-APP-000427-WSR-000186'
  end

  control 'V-76817' do
    tag "cci": ['CCI-001310']
    tag "nist": ['SI-10', 'Rev_4']
    desc 'caveat', 'SC-5(1) is not listed in ARS, but the ARS SI-10 clearly implies the 
         need for these fields in event records. As a result, the associated NIST 
         control has been changed to SI-10.'
  end

  control 'V-76819' do
    tag "cci": ['CCI-001310']
    tag "nist": ['SI-10', 'Rev_4']
    desc 'caveat', 'SC-5(1) is not listed in ARS, but the ARS SI-10 clearly implies the                       
         need for these fields in event records. As a result, the associated NIST                             
         control has been changed to SI-10.'
  end

  control 'V-76821' do
    tag "cci": ['CCI-001310']
    tag "nist": ['SI-10', 'Rev_4']
    desc 'caveat', 'SC-5(1) is not listed in ARS, but the ARS SI-10 clearly implies the                       
         need for these fields in event records. As a result, the associated NIST                             
         control has been changed to SI-10.'
  end

  control 'V-76823' do	
    tag "cci": ['CCI-001310']
    tag "nist": ['SI-10', 'Rev_4']
    desc 'caveat', 'SC-5(1) is not listed in ARS, but the ARS SI-10 clearly implies the                       
         need for these fields in event records. As a result, the associated NIST                             
         control has been changed to SI-10.'
  end

  control 'V-76825' do	
    tag "cci": ['CCI-001310']
    tag "nist": ['SI-10', 'Rev_4']
    desc 'caveat', 'SC-5(1) is not listed in ARS, but the ARS SI-10 clearly implies the                       
         need for these fields in event records. As a result, the associated NIST                             
         control has been changed to SI-10.'
  end

  control 'V-76827' do	
    tag "cci": ['CCI-001310']
    tag "nist": ['SI-10', 'Rev_4']
    desc 'caveat', 'SC-5(1) is not listed in ARS, but the ARS SI-10 clearly implies the                       
         need for these fields in event records. As a result, the associated NIST                             
         control has been changed to SI-10.'
  end
  
  control 'V-76847' do
    title 'The IIS 8.5 websites must utilize ports, protocols, and services 
          according to CMS guidelines.'
    desc 'Web servers provide numerous processes, features, and functionalities 
         that utilize TCP/IP ports. Some of these processes may be deemed 
         unnecessary or too unsecure to run on a production system.

         The web server must provide the capability to disable or deactivate 
         network-related services that are deemed to be non-essential to the 
         server mission, are too unsecure, or are prohibited by CMS and 
         vulnerability assessments.

         Failure to comply with CMS ports, protocols, and services (PPS) 
         requirements can result in compromise of enclave boundary protections 
         and/or functionality of the Information System.

         The ISSO will ensure web servers are configured to use only necessary 
         ports, protocols, and services.'
    desc 'check', 'Review the website to determine if HTTP and HTTPs (e.g., 
                  80 and 443) are used.

                  Follow the procedures below for each site hosted on 
                  the IIS 8.5 web server:

                  Open the IIS 8.5 Manager.

                  Click the site name under review.

                  In the Action Pane, click Bindings.

                  Review the ports and protocols. If unknown ports or protocols 
                  are used, then this is a finding.'
  end

  control 'V-76849' do
    title 'The IIS 8.5 private website have a server certificate issued by CMS 
          PKI or CMS-approved PKI Certification Authorities (CAs).'
    desc 'The use of a CMS PKI certificate ensures clients the private website
         they are connecting to is legitimate, and is an essential part of the CMS
         defense-in-depth strategy.'
    desc 'check', 'Follow the procedures below for each site hosted on the IIS 8.5 
         web server:

         Open the IIS 8.5 Manager.
         
         Click the site name under review.

         Click Bindings in the Action Pane.

         Click the HTTPS type from the box.

         Click Edit.

         Click View and then review and verify the certificate path.

         If the list of CAs in the trust hierarchy does not lead to the CMS PKI Root 
         CA, CMS-approved external certificate authority (ECA), or CMS-approved 
         external partner, this is a finding.

         If HTTPS is not an available type under site bindings, this is a finding.'
    desc 'fix', 'Follow the procedures below for each site hosted on the IIS 8.5 
         web server:

         Open the IIS 8.5 Manager.

         Click the Server name.

         Double-click Server Certificates.

         Click Import under the "Actions" pane.

         Browse to the CMS certificate location, select it, and click OK.

         Remove any non-CMS certificates if present.

         Click on the site needing the certificate.

         Select Bindings under the "Actions" pane.

         Click on the binding needing a certificate and select Edit, or 
         add a site binding for HTTPS.

         Assign the certificate to the website by choosing it under the SSL Certificate 
         drop-down and clicking OK.'
    describe "For this CMS ARS 3.1 overlay, this control must be reviewed manually" do 
      skip "For this CMS ARS 3.1 overlay, this control must be reviewed manually"
    end
  end

  control 'V-76861' do
    impact "none"
    desc 'caveat': "Not applicable for this CMS ARS 3.1 overlay, since the related 
          security control is not mandatory in CMS ARS 3.1"
  end

  control 'V-76867' do
    desc 'check', 'Note: Recycling Application Pools can create an unstable environment 
         in a 64-bit SharePoint environment. If operational issues arise, with 
         supporting documentation from the ISSO, this check can be downgraded to a Low 
         Impact/Severity.

         Open the IIS 8.5 Manager.

         Perform for each Application Pool.

         Click the â€œApplication Pools.

         Highlight an Application Pool and click "Advanced Settings" in the Action Pane.

         Scroll down to the "Recycling section" and verify the value for "Request Limit" 
         is set to a value other than "0".

         If the "Request Limit" is set to a value of "0", this is a finding.'
  end

  control 'V-76869' do
    desc 'check', 'Note: Recycling Application Pools can create an unstable environment 
         in a 64-bit SharePoint environment. If operational issues arise, mitigation 
         steps can be set, to include setting the Fixed number or requests, Specific 
         time, and Private memory usage in the recycling conditions lieu of the 
         Virtual memory setting. If mitigation is used in lieu of this requirement, 
         with supporting documentation from the ISSO, this check can be downgraded 
         to a Low Impact/Severity.

         Open the IIS 8.5 Manager.

         Perform for each Application Pool.

         Click on Application Pools.

         Highlight an Application Pool and click "Advanced Settings" in the Action Pane.

         In the "Advanced Settings" dialog box scroll down to the "Recycling" section 
         and verify the value for "Virtual Memory Limit" is not set to 0.

         If the value for "Virtual Memory Limit" is set to 0, this is a finding.'
  end

  control 'V-76871' do
    desc 'check', 'Note: Recycling Application Pools can create an unstable environment 
         in a 64-bit SharePoint environment. If operational issues arise, with supporting 
         documentation from the ISSO this check can be downgraded to a Low Impact/Severity.

         Open the IIS 8.5 Manager.

         Perform for each Application Pool.

         Click the Application Pools.

         Highlight an Application Pool and click "Advanced Settings" in the Action Pane.

         Scroll down to the "Recycling" section and verify the value for "Private Memory 
         Limit" is set to a value other than "0".

         If the "Private Memory Limit" is set to a value of "0", this is a finding.'
  end

  control 'V-76873' do
    desc 'check', 'Note: Recycling Application Pools can create an unstable environment 
         in a 64-bit SharePoint environment. If operational issues arise, with supporting 
         documentation from the ISSO this check can be downgraded to a Low Impact/Severity.

         Open the IIS 8.5 Manager.

         Perform for each Application Pool.

         Click the Application Pools.

         Highlight an Application Pool and click "Advanced Settings" in the Action Pane.

         Scroll down to the "Recycling" section and expand the "Generate Recycle Event 
         Log Entry" section.

         Verify both the "Regular time interval" and "Specific time" options are set to 
         "True".

         If both the "Regular time interval" and "Specific time" options are not set to 
         "True", this is a finding.'
  end
  
  control 'V-76891' do
    title 'The required CMS banner page must be displayed to authenticated users accessing 
          a CMS private website.'
    desc 'A consent banner will be in place to make prospective entrants aware that the 
         website they are about to enter is a CMS web site and their activity is subject 
         to monitoring.

         The requirement for the banner is for websites with security and access controls. 
         These are restricted and not publicly accessible. If the website does not require 
         authentication/authorization for use, then the banner does not need to be present. 
         A manual check of the document root directory for a banner page file (such as 
         banner.html) or navigation to the website via a browser can be used to confirm the 
         information provided from interviewing the web staff.'
    desc 'check', 'Note: This requirement is only applicable for private CMS websites.

         If a banner is required, the following banner page must be in place: 

         * This warning banner provides privacy and security notices consistent with 
         applicable federal laws, directives, and other federal guidance for accessing this 
         Government system, which includes (1) this computer network, (2) all computers 
         connected to this network, and (3) all devices and storage media attached to this 
         network or to a computer on this network.  

         * This system is provided for Government authorized use only.  
         
         * Unauthorized or improper use of this system is prohibited and may result in 
         disciplinary action and/or civil and criminal penalties.  
         
         * Personal use of social media and networking sites on this system is limited as to 
         not interfere with official work duties and is subject to monitoring.  

         * By using this system, you understand and consent to the following:   

                  - The Government may monitor, record, and audit your system usage, including usage 
                  of personal devices and email systems for official duties or to conduct HHS 
                  business. Therefore, you have no reasonable expectation of privacy regarding any 
                  communication or data transiting or stored on this system. At any time, and for any 
                  lawful Government purpose, the government may monitor, intercept, and search and 
                  seize any communication or data transiting or stored on this system.     
         
                  - Any communication or data transiting or stored on this system may be disclosed or 
                   used for any lawful Government purpose. 

         If the access-controlled website does not display this banner page before entry, 
         this is a finding.'
    desc 'fix', 'Configure a CMS private website to display the required CMS banner page when 
         authentication is required for user access.'
    
    describe 'Manual review of website is needed' do
      skip "Manual review that required CMS banner page is displayed to authenticated 
           users accessing a CMS private website"
    end
  end
end

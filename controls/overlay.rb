# encoding: utf-8
include controls 'microsoft-iis-8.5-site-stig-baseline' do
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

  control 'V-76839' do
    desc 'The idle time-out attribute controls the amount of time a worker process will 
         remain idle before it shuts down. A worker process is idle if it is not processing 
         requests and no new requests are received.

         The purpose of this attribute is to conserve system resources; the default value 
         for idle time-out is 30 minutes.

         By default, the World Wide Web (WWW) service establishes an overlapped recycle, 
         in which the worker process to be shut down is kept running until after a new worker 
         process is started.'
    desc 'check', 'Follow the procedures below for each site hosted on the IIS 8.5 web server:

         Open the IIS 8.5 Manager.

         Click the Application Pools.

         Highlight an Application Pool to review and click "Advanced Settings" in the 
         "Actions" pane.

         Scroll down to the "Process Model" section and verify the value for "Idle Time-out" 
         is set to "30".

         If the "Idle Time-out" is not set to "30" or less, this is a finding'
    desc 'fix', 'Follow the procedures below for each site hosted on the IIS 8.5 web server:

         Open the IIS 8.5 Manager.

         Click the Application Pools.

         Highlight an Application Pool to review and click "Advanced Settings" in the 
         "Actions" pane.

         Scroll down to the "Process Model" section and set the value for "Idle Time-out" 
         to "30" or less.'
    get_names = command("Get-Website | select name | findstr /v 'name ---'").stdout.strip.split("\r\n")
    get_idleTimeout_monitor = command('Get-WebConfigurationProperty -pspath "IIS:\Sites\*" 
                                       -Filter system.applicationHost/applicationPools\ -name * |       
                                       select -expand applicationPoolDefaults | 
                                       select -expand processModel | select -expand idleTimeout | 
                                       select -expand TotalMinutes').stdout.strip.split("\r\n")

    get_idleTimeout_monitor.zip(get_names).each do |idleTimeout_monitor, names|
      n = names.strip

      describe "The IIS site: #{n} websites idle monitor time-out" do
        subject { idleTimeout_monitor }
        it { should cmp <= 30 }
      end
    end
    if get_names.empty?
      impact 0.0
      desc 'There are no IIS sites configured hence the control is Not-Applicable'
      
      describe 'No sites where found to be reviewed' do
        skip 'No sites where found to be reviewed'
      end
    end
  end
  
  control 'V-76841' do
    desc 'Leaving sessions open indefinitely is a major security risk. An attacker 
         can easily use an already authenticated session to access the hosted 
         application as the previously authenticated user. By closing sessions after 
         a set period of inactivity, the web server can make certain that those sessions 
         that are not closed through the user logging out of an application are 
         eventually closed.'
    desc 'check', 'Follow the procedures below for each site hosted on the IIS 8.5 
                  web server:

                  Open the IIS 8.5 Manager.

                  Click the site name.

                  Select "Configuration Editor" under the "Management" section.

                  From the "Section:" drop-down list at the top of the configuration 
                  editor, locate "system.web/sessionState".

                  Verify the "timeout" is set to "00:30:00 or less.

                  If "timeout" is not set to "00:30:00 or less, this is a finding.'
    desc 'fix', 'Follow the procedures below for each site hosted on the IIS 8.5 
                web server:

                Open the IIS 8.5 Manager.

                Click the site name.

                Select "Configuration Editor" under the "Management" section.

                From the "Section:" drop-down list at the top of the configuration 
                editor, locate "system.web/sessionState". 

                Set the "timeout" to "00:30:00 or less.
                
                In the "Actions" pane, click "Apply".'

    get_names = command("Get-Website | select name | 
                        findstr /v 'name ---'").stdout.strip.split("\r\n")
    get_connectionTimeout = command('Get-WebConfigurationProperty -pspath "IIS:\Sites\*" 
                                     -Filter system.web/sessionState -name * | 
                                     select -expand timeout | 
                                     select -expand TotalMinutes').stdout.strip.split("\r\n")
    get_connectionTimeout.zip(get_names).each do |connectionTimeout, names|
      n = names.strip

      describe "The IIS site: #{n} websites connection timeout" do
        subject { connectionTimeout }
        it { should cmp <= 30 }
      end
    end
    if get_names.empty?
      impact 0.0
      desc 'There are no IIS sites configured hence the control is Not-Applicable'
      describe 'No sites where found to be reviewed' do
        skip 'No sites where found to be reviewed'
      end
    end
  end

  control 'V-76847' do
    desc 'The IIS 8.5 websites must only utilize the ports, protocols, 
         and services required for its mission.'
    desc 'check', 'Web servers provide numerous processes, features, 
                  and functionalities that utilize TCP/IP ports. Some 
                  of these processes may be deemed unnecessary or too 
                  unsecure to run on a production system.

                  The web server must provide the capability to disable 
                  or deactivate network-related services that are deemed 
                  to be non-essential to the server mission, are too 
                  unsecure, or are prohibited.

                  The ISSM will ensure web servers are configured to use 
                  only authorized ports, protocols, and services.'
    desc 'fix', 'Review the website to determine if HTTP and HTTPs (e.g., 
                80 and 443) are used in accordance with those ports and 
                services approved for use by CMS ARS. 

                Follow the procedures below for each site hosted on the 
                IIS 8.5 web server:

                Open the IIS 8.5 Manager.

                Click the site name under review.

                In the Action Pane, click Bindings.

                Review the ports and protocols. If unknown ports or 
                protocols are used, then this is a finding.'
  end

  control 'V-76891' do
    title 'The required CMS banner page must be displayed to authenticated users 
          accessing a CMS private website.'
    desc 'A consent banner will be in place to make prospective entrants aware that the 
         website they are about to enter is a CMS web site and their activity is subject 
         to monitoring. It requires the use of a standard CMS Notice and Consent Banner 
         and standard text to be included in user agreements. The requirement for the 
         banner is for websites with security and access controls. These are restricted 
         and not publicly accessible. If the website does not require 
         authentication/authorization for use, then the banner does not need to be 
         present. A manual check of the document root directory for a banner page file 
         (such as banner.html) or navigation to the website via a browser can be used to 
         confirm the information provided from interviewing the web staff.'
    desc 'check', 'Note: This requirement is only applicable for private CMS websites.

         If a banner is required, the following banner page must be in place: 

         * This warning banner provides privacy and security notices consistent with 
         applicable federal laws, directives, and other federal guidance for accessing 
         this Government system, which includes (1) this computer network, (2) all 
         computers connected to this network, and (3) all devices and storage media 
         attached to this network or to a computer on this network.

         * This system is provided for Government authorized use only.
         
         * Unauthorized or improper use of this system is prohibited and may result 
         in disciplinary action and/or civil and criminal penalties.
         
         * Personal use of social media and networking sites on this system is limited 
         as to not interfere with official work duties and is subject to monitoring.

         * By using this system, you understand and consent to the following:
         
         - The Government may monitor, record, and audit your system usage, including 
         usage of personal devices and email systems for official duties or to conduct 
         HHS business. Therefore, you have no reasonable expectation of privacy regarding 
         any communication or data transiting or stored on this system. At any time, and 
         for any lawful Government purpose, the government may monitor, intercept, and 
         search and seize any communication or data transiting or stored on this system.

         - Any communication or data transiting or stored on this system may be disclosed 
         or used for any lawful Government purpose

         If the access-controlled website does not display this banner page before entry, 
         this is a finding.'
    desc 'fix', 'Configure a CMS private website to display the required CMS banner page 
         when authentication is required for user access.'
    
    describe 'Manual review of website is needed' do
      skip "Manual review that required CMS banner page is displayed to authenticated 
           users accessing a CMS private website"
    end
  end
end

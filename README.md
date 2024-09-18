# SOC Automation Project

## Objective

The goal of this SOC automation project was to develop a seamless workflow that organizes and enriches logs from client machines by integrating multiple platforms, including Wazuh, VirusTotal, and SOAR solutions like Shuffle. The aim was to automate the process of flagging critical alerts and forwarding them directly to a SOC analyst's email for immediate action.

In this setup, we used Mimikatz to simulate a vulnerability, triggering a syslog event on the client machine. This event was forwarded via the Wazuh agent, where a custom detection rule flagged the Mimikatz activity and generated an alert. The alert was then logged in The Hive SOAR platform, and an automated email notification was sent to the SOC analyst. All platform interactions were orchestrated through Shuffle using RESTful APIs, ensuring an efficient and cohesive response to critical events.

## Skills Learned
- Cloud server setup and management (DigitalOcean)
- Firewall configuration for secure network access
- SSH configuration and management
- Installation and configuration of Wazuh and The Hive SOAR platform
- API integration between Wazuh, VirusTotal, and Shuffle
- Rule creation in Wazuh for custom detection (Mimikatz)
- Log analysis using Sysmon and Wazuh
- SOAR automation through Shuffle
- RESTful API integration for automated workflows
- JSON manipulation for API-driven alerting and notifications
- Dynamic email automation for SOC analyst notifications

## Tools Used
- **Wazuh**: Security monitoring and log analysis
- **The Hive**: SOAR platform for security incident management
- **Shuffle**: SOAR automation tool
- **VirusTotal**: Threat analysis platform
- **Sysmon**: Windows system monitoring tool
- **Mimikatz**: Penetration testing tool to simulate an attack
- **DigitalOcean**: Cloud hosting provider for servers
- **SSH**: Secure shell for server access and management
- **RESTful APIs**: For platform integrations

## Project Steps

1. Created two servers on a cloud provider (DigitalOcean) hosting Wazuh and The Hive.

2. Configured a firewall with rules allowing incoming connections from my public IP.

3. SSH'd into the first server and installed Wazuh dependencies.

4. SSH'd into the second server and installed The Hive dependencies such as Java, Cassandra, and Elasticsearch.

5. Edited the `cassandra.yaml` file on The Hive server to set the listen address, RPC address, and seeds IP to the public IP of the server, ensuring Cassandra is reachable from other machines.

6. Configured the `elasticsearch.yml` file on The Hive server by setting the server's public IP as the network host.

7. Edited The Hive's `application.conf` file to set the hostname and `application.baseURL` to the server's public IP and matched the cluster name with Cassandra's configuration.

8. Once all dependencies were running, The Hive was successfully accessible via the server's public IP.

9. Deployed a new Wazuh agent on the Windows 11 client by generating a command from the Wazuh manager and running it on the client:
    ```bash
    Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.5-1.msi -OutFile ${env.tmp}\wazuh-agent; msiexec.exe /i ${env.tmp}\wazuh-agent /q WAZUH_MANAGER='Public-IP' WAZUH_AGENT_NAME='Dfir' WAZUH_REGISTRATION_SERVER='165.232.186.78'
    ```

10. Verified that Wazuh was successfully running on the Windows 11 client.

11. Edited the `ossec.conf` file on the Windows client to include Sysmon logs for detecting Mimikatz activity.

12. Downloaded the Mimikatz executable and configured Wazuh to log all events, including those stored in its archives. Created a custom rule in Wazuh (ID 1: process creation) to trigger an alert when an executable with the original filename "mimikatz" was run.

13. Verified that Sysmon events, including Mimikatz execution, were being logged by Wazuh.

14. Connected Shuffle with Wazuh using the webhook trigger tool by adding the webhook URI to Wazuh's `ossec.conf` file. Configured it to only send alerts with rule_id `100002` (Mimikatz detection) to Shuffle.

15. Set up a workflow in Shuffle to capture the SHA-512 hash of the executable and send it to VirusTotal for analysis via the API, using regex capture in Shuffle to extract the hash.

16. Integrated Shuffle with The Hive by using The Hive's API key to create an alert based on the VirusTotal analysis. Configured the alert with dynamic parameters in JSON format.

17. Verified that an alert was successfully created in The Hive on the SOC analyst's account.

18. Configured an automated email workflow in Shuffle, sending a dynamic alert notification to my school email, which can be reused for future alerts beyond Mimikatz.



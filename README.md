# SOC Automation Project

## Objective

The goal of this SOC automation project was to develop a seamless workflow that organizes and enriches logs from client machines by integrating multiple platforms, including Wazuh, VirusTotal, and SOAR solutions like Shuffle. The aim was to automate the process of flagging critical alerts and forwarding them directly to a SOC analyst's email for immediate action.

In this setup, we used Mimikatz to simulate a vulnerability, triggering a syslog event on the client machine. This event was forwarded via the Wazuh agent, where a custom detection rule flagged the Mimikatz activity and generated an alert. The alert was then logged in The Hive SOAR platform, and an automated email notification was sent to the SOC analyst. All platform interactions were orchestrated through Shuffle using RESTful APIs, ensuring an efficient and cohesive response to critical events.

## Skills Learned
- Cloud server setup and management
- Firewall configuration for secure network access
- SSH configuration and management
- Installation and configuration of Wazuh and The Hive SOAR platform
- API integration between Wazuh, VirusTotal, and Shuffle
- Rule creation in Wazuh for custom detection
- Log analysis using Sysmon and Wazuh
- SOAR automation through Shuffle
- RESTful API integration for automated workflows

## Tools Used
- **Wazuh**: Security monitoring and log analysis
- **The Hive**: SOAR platform for security incident management
- **Shuffle**: SOAR automation tool
- **VirusTotal**: Threat analysis platform
- **Sysmon**: Windows system monitoring tool
- **Mimikatz**: Penetration testing tool to simulate an attack
- **DigitalOcean**: Cloud hosting provider for servers
- **RESTful APIs**: For platform integrations

## Project Steps

1. Created two servers on a cloud provider (DigitalOcean) hosting Wazuh and The Hive.

<img width="944" alt="Screenshot 2024-09-18 at 4 16 17 PM" src="https://github.com/user-attachments/assets/5feaa52d-4d4d-495d-85b2-8888d2e6bbce">

2. Configured a firewall with rules allowing incoming connections from my public IP.

<img width="802" alt="Screenshot 2024-09-18 at 4 16 38 PM" src="https://github.com/user-attachments/assets/7f879da0-547f-47fb-91ea-5d9b55d3ae84">

3. SSH'd into the first server and installed Wazuh dependencies.

<img width="975" alt="Screenshot 2024-09-18 at 4 17 28 PM" src="https://github.com/user-attachments/assets/2e37987f-c6c0-471d-8f27-375c5852f42d">

4. SSH'd into the second server and installed The Hive dependencies such as Java, Cassandra, and Elasticsearch.

5. Edited the `cassandra.yaml` file on The Hive server to set the listen address, RPC address, and seeds IP to the public IP of the server, ensuring Cassandra is reachable from other machines.

<img width="971" alt="Screenshot 2024-09-18 at 4 17 54 PM" src="https://github.com/user-attachments/assets/13ed7ad5-c068-4637-9c7d-962672aa2d73">

6. Configured the `elasticsearch.yml` file on The Hive server by setting the server's public IP as the network host.

<img width="973" alt="Screenshot 2024-09-18 at 4 19 07 PM" src="https://github.com/user-attachments/assets/3867b34f-882a-4c03-a88f-e5b24d553e1f">

7. Edited The Hive's `application.conf` file to set the hostname and `application.baseURL` to the server's public IP and matched the cluster name with Cassandra's configuration.

<img width="968" alt="Screenshot 2024-09-18 at 4 18 12 PM" src="https://github.com/user-attachments/assets/7fded6c4-cc06-4b6c-a5d4-399901c8a074">

8. Once all dependencies were running, The Hive was successfully accessible via the server's public IP.

<img width="809" alt="Screenshot 2024-09-18 at 4 19 27 PM" src="https://github.com/user-attachments/assets/f8d038da-67a6-4c1f-8c9a-87fb0430f812">

9. Deployed a new Wazuh agent on the Windows 11 client by generating a command from the Wazuh manager and running it on the client:
    ```bash
    Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.5-1.msi -OutFile ${env.tmp}\wazuh-agent; msiexec.exe /i ${env.tmp}\wazuh-agent /q WAZUH_MANAGER='Public-IP' WAZUH_AGENT_NAME='Dfir' WAZUH_REGISTRATION_SERVER='165.232.186.78'
    ```

<img width="1028" alt="Screenshot 2024-09-18 at 4 19 44 PM" src="https://github.com/user-attachments/assets/ba6ee18d-5ead-47fd-b5f8-6bb991fb4db5">

10. Verified that Wazuh was successfully running on the Windows 11 client.

<img width="1019" alt="Screenshot 2024-09-18 at 4 20 09 PM" src="https://github.com/user-attachments/assets/b47ec376-f1b2-4d26-b528-9060f895f651">

11. Edited the `ossec.conf` file on the Windows client to include Sysmon logs for detecting Mimikatz activity.

<img width="996" alt="Screenshot 2024-09-18 at 4 20 44 PM" src="https://github.com/user-attachments/assets/64922262-8f4e-4108-9e4a-e8b39036f613">

12. Downloaded the Mimikatz executable and configured Wazuh to log all events, including those stored in its archives. Created a custom rule in Wazuh (ID 1: process creation) to trigger an alert when an executable with the original filename "mimikatz" was run.

<img width="967" alt="Screenshot 2024-09-18 at 4 21 54 PM" src="https://github.com/user-attachments/assets/35c91c93-1139-48ea-b8af-4b29ede2c76c">

13. Verified that Sysmon events, including Mimikatz execution, were being logged by Wazuh.

<img width="892" alt="Screenshot 2024-09-18 at 4 22 15 PM" src="https://github.com/user-attachments/assets/a9382c6b-bd26-4eda-9cf3-3d7cd55b3226">

14. Connected Shuffle with Wazuh using the webhook trigger tool by adding the webhook URI to Wazuh's `ossec.conf` file. Configured it to only send alerts with rule_id `100002` (Mimikatz detection) to Shuffle.

<img width="719" alt="Screenshot 2024-09-18 at 4 22 51 PM" src="https://github.com/user-attachments/assets/dbf0a6de-b0d7-4ddd-a9e2-17d8cdeff18a">

15. Set up a workflow in Shuffle to capture the SHA-512 hash of the executable and send it to VirusTotal for analysis via the API, using regex capture in Shuffle to extract the hash.

<img width="718" alt="Screenshot 2024-09-18 at 4 23 07 PM" src="https://github.com/user-attachments/assets/76a6a2fb-92d7-4997-b2cd-c8462872ef6e">
<img width="606" alt="Screenshot 2024-09-18 at 4 23 28 PM" src="https://github.com/user-attachments/assets/e4b8511e-89eb-4890-a01f-4e169ebb8ff7">

16. Integrated Shuffle with The Hive by using The Hive's API key to create an alert based on the VirusTotal analysis. Configured the alert with dynamic parameters in JSON format.

<img width="817" alt="Screenshot 2024-09-18 at 4 23 45 PM" src="https://github.com/user-attachments/assets/ad7e8200-08cc-4263-ad21-dddb735ddead">

17. Verified that an alert was successfully created in The Hive on the SOC analyst's account.

<img width="827" alt="Screenshot 2024-09-18 at 4 24 04 PM" src="https://github.com/user-attachments/assets/56f9c53c-0dc9-422b-9465-fdd202059c83">

18. Configured an automated email workflow in Shuffle, sending a dynamic alert notification to my school email, which can be reused for future alerts beyond Mimikatz.
<img width="652" alt="Screenshot 2024-09-18 at 4 24 30 PM" src="https://github.com/user-attachments/assets/5bcf0744-3dcd-4c34-97d6-d25b45f7d957">
<img width="870" alt="Screenshot 2024-09-18 at 4 24 48 PM" src="https://github.com/user-attachments/assets/b383abe4-735f-44fd-a59d-96a0285e6da3">




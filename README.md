 # MISP + Pi-hole + Squid Proxy Installation Guide
 
 This README provides step-by-step instructions for installing both **MISP** (Malware Information Sharing Platform), **Pi-hole** and **Squid proxy** on a Ubuntu-based system (tested on Ubuntu 24.04). The process uses the official installation scripts from each project’s GitHub repository.
 
 ---
 
 ## Important
 
 - These scripts assume you have **sudo** or **root** privileges.  
 - MISP, Pi-hole, Squid proxy each have their own dependencies; ensure your system is up-to-date before proceeding.  
 - If you plan to run both on the **same machine**, verify that there are no port conflicts (e.g., Pi-hole typically runs a DNS service and a web dashboard).  
 - Consult each project’s official documentation for more advanced configuration.
 
 ---
 
 ## Prerequisites
 
 ### Operating System
 - Ubuntu 24.04 LTS
 
 ### Run the install.sh - It will install MISP, Pi-Hole an then Squid proxy
 ```bash
chmod +x install.sh
sudo ./install.sh
 ```
 ### During installation (Pi-hole Automated Installer)
 Welcome page
 
 <img width="794" height="519" alt="Screenshot 2025-11-29 at 20 55 23" src="https://github.com/user-attachments/assets/0ca5fcbf-1dff-41c0-be3b-0fd3110807e7" />
 
 In prototype, using local host IP 127.0.0.1, so "continue"

 <img width="794" height="519" alt="Screenshot 2025-11-29 at 20 58 15" src="https://github.com/user-attachments/assets/44b9997b-a320-4f38-a41a-177595e7bef4" />

 In prototype, using unfiltered, no DNSSEC, but can be others

 <img width="794" height="519" alt="Screenshot 2025-11-29 at 21 02 15" src="https://github.com/user-attachments/assets/28df7d81-0ff7-4310-9a4d-0b9b35588e63" />

Since using MISP, it is not needed

<img width="794" height="519" alt="Screenshot 2025-11-29 at 21 05 10" src="https://github.com/user-attachments/assets/2029d05c-3e42-4ae4-b558-9ef05a0d1ce4" />

Important for retrohunt, "yes"

<img width="794" height="519" alt="Screenshot 2025-11-29 at 21 07 26" src="https://github.com/user-attachments/assets/f0e6b8bb-bd00-4e40-8fec-b636e77af620" />

For retrohunt, logs needed, "continue"

<img width="794" height="519" alt="Screenshot 2025-11-29 at 21 08 39" src="https://github.com/user-attachments/assets/0ff03761-bf38-4990-8718-99311fee1644" />



 

 
 ### After script finish
Use the Pihole password to login:
![image](https://github.com/user-attachments/assets/88c02bf8-dd77-4b9f-87e2-214724fb8749)
Open misp link (have to trust certificate) from terminal and Scroll up from the terminal and look for the MISP username and password
 ![image](https://github.com/user-attachments/assets/10a328bb-f9e5-4895-8a03-d02232050f3b)
Change the password and you are in!

Add new API key for your MISP admin account, fields can be left empty
![image](https://github.com/user-attachments/assets/2b1e4ea9-4077-4731-9a72-cb744544566a)
Add your key to misp-to-pihole.py AND also add the key to misp-to-proxy.py and misp-retrohunt.py (var name MISP_API_KEY)
![image](https://github.com/user-attachments/assets/de7dc2fd-b4b3-49be-a6bc-03ad98c169c7)

Enable MISP feeds

![image](https://github.com/user-attachments/assets/66771717-1c81-4051-b5c3-c9b8456b0845)
![image](https://github.com/user-attachments/assets/349bb8b9-9828-438b-b5a2-1bff7c593b41)
Click on the balck button with white arrow down, will see the Green box pop up
![image](https://github.com/user-attachments/assets/30981fc6-853b-4702-88a9-1a2a4df182d2)
Click on the Home button and make sure you have some events
![image](https://github.com/user-attachments/assets/19dd9c26-5db6-46f3-af30-5ff5c700201f)



 ## Run misp-to-pihole.py
Before running script see how many blocked domains you have
![image](https://github.com/user-attachments/assets/501c419c-ea89-4ad4-b6f1-9937e87167b5)
Now go terminal and run script
 ```bash
chmod +x misp-to-pihole.py
sudo ./misp-to-pihole.py
 ```
![image](https://github.com/user-attachments/assets/0410005a-f65b-419f-a5e3-7d23348bc36d)

Add the script to run domains from MISP to Pi-hole every six hours and fetch MISP all enabled feeds:
```
sudo crontab -e
```
Add line using 1 for nano editor (we use one command to get new feeds for MISP and then wait for 5 minutes and then load the domains in to Pi-hole database):
```
0 */6 * * * bash -c 'sudo -u www-data /var/www/MISP/app/Console/cake Server fetchFeed 1 all && sleep 300 && /{YourFileLocation}/misp-to-pihole.py'
```
![image](https://github.com/user-attachments/assets/52406925-d28c-4ec6-95ab-f6bc739ceafc)

Go chek if its in the Pihole WebGUI
![image](https://github.com/user-attachments/assets/7b236e33-86bb-4435-8c03-8f3857812ccb)

## Run misp-to-proxy.py

 ```bash
chmod +x misp-to-proxy.py
sudo ./misp-to-proxy.py
 ```
Output is something like that:

<img width="1850" height="681" alt="Screenshot 2025-11-29 at 22 32 15" src="https://github.com/user-attachments/assets/a6639876-b218-49da-871c-83229bade794" />

Change browser proxy settings (in prototype Firefox is used)
Settings -> Network settings -> Connection setting (window popup)

<img width="1283" height="780" alt="Screenshot 2025-11-29 at 22 52 14" src="https://github.com/user-attachments/assets/47397804-eeb5-4120-874f-b4a156d049c1" />

### Test scenario for Squid proxy:
Add event

<img width="1135" height="772" alt="Screenshot 2025-11-29 at 23 04 41" src="https://github.com/user-attachments/assets/bf47a777-a15e-43e2-8659-27e48a526d05" />

Adding atribute to MISP event to block specific url

<img width="1335" height="772" alt="Screenshot 2025-11-29 at 23 08 15" src="https://github.com/user-attachments/assets/8686775e-9764-4dbd-adaa-36312e1834b2" />

Block Reddit url exc.

<img width="1335" height="772" alt="Screenshot 2025-11-29 at 23 09 54" src="https://github.com/user-attachments/assets/fd819563-2e30-4a4c-836d-64375cfc00bd" />

Submit attributes

<img width="1335" height="772" alt="Screenshot 2025-11-29 at 23 11 16" src="https://github.com/user-attachments/assets/dac6c780-0304-45bb-8be3-577d04fbaaa4" />

Publish event, "yes"

<img width="1335" height="772" alt="Screenshot 2025-11-29 at 23 12 13" src="https://github.com/user-attachments/assets/8ea94aeb-2e05-42da-b96f-13fd04eb7d6a" />

Rerun the misp-to-proxy.py
Now the url is blocked:

<img width="1335" height="425" alt="Screenshot 2025-11-29 at 23 14 56" src="https://github.com/user-attachments/assets/e47d83f3-d929-4946-84bd-188699236f47" />

## Run misp-retrohunt.py
Before running retrohunt script:
1) proxy logs needed- already have, because Firefox proxy settings are changed
2) DNS logs needed- need to configure
How to get DNS logs:
Change Ubuntu network settings to use Pi-hole as DNS server

<img width="973" height="634" alt="Screenshot 2025-11-29 at 23 24 29" src="https://github.com/user-attachments/assets/fa62c5de-ebda-40f1-a129-5bceb78b4ad4" />

### Test scenario for retrohunt

Visiting 2 webpages
Creating new MISP event
Populate from -> Freetext Import Tool -> then add thoses visited urls and domains

<img width="1490" height="732" alt="Screenshot 2025-11-29 at 23 36 36" src="https://github.com/user-attachments/assets/6355dc05-5891-4f0b-8445-322e2e07bc13" />

Verify and submit attributes

<img width="1490" height="732" alt="Screenshot 2025-11-29 at 23 40 27" src="https://github.com/user-attachments/assets/713f1a99-3f2e-4a72-a6ef-db4cea6a3d47" />

Now, click Publish (no email)

```bash
chmod +x misp-retrohunt.py
sudo ./misp-retrohunt.py
 ```
After script, in the output visible: 2 new events- one for Squid and one for Pi-hole

<img width="1120" height="163" alt="Screenshot 2025-11-29 at 23 54 46" src="https://github.com/user-attachments/assets/5089fff4-fa15-4018-aaae-8980af0daa01" />

Results are visible under those events, notified that potentially malicious urls were clicked











 ## Run dns_test.py - to measure performance
Dowmload the script:
 ```bash
chmod +x dns_test.py
./dns_test.py
 ```
Clean the database if needed:
```
sudo sqlite3 /etc/pihole/gravity.db "DELETE FROM domainlist"
```
![image](https://github.com/user-attachments/assets/32222afb-0ccd-42f6-aa89-fccb9222f765)
Run script and then load blocked domains again to database:
![image](https://github.com/user-attachments/assets/d05948ef-42b3-48f0-9449-1520f974cd53)

 
 ## References & Further Reading
 
 - **MISP Documentation**:  
   [https://github.com/MISP/MISP](https://github.com/MISP/MISP)
 - **Pi-hole Documentation**:  
   [https://github.com/pi-hole/pi-hole](https://github.com/pi-hole/pi-hole)
 - **Pi-hole Basic Install Script**:  
   [https://github.com/pi-hole/pi-hole/blob/master/automated%20install/basic-install.sh](https://github.com/pi-hole/pi-hole/blob/master/automated%20install/basic-install.sh) 
 - **Squid Documentation**:
   [https://www.squid-cache.org/Doc/]
   
   
 ```


🦊 2. Firefox trust

Firefox ignores the OS trust store by default and uses its own certificate DB per-profile.

Option A — Import manually

Open Firefox → Settings → Privacy & Security

Scroll to Certificates → click View Certificates…

Go to the Authorities tab → click Import

Choose /etc/squid/ssl_cert/myCA.crt

When asked, check:

☑ Trust this CA to identify websites

(Optional) Trust for email users

Restart Firefox

Now open https://google.com — no more warning if proxied through Squid.

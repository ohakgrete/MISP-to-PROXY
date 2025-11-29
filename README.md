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

Add new API key for your MISP admin account
![image](https://github.com/user-attachments/assets/2b1e4ea9-4077-4731-9a72-cb744544566a)
Add your key to misp-to-pihole.py 
![image](https://github.com/user-attachments/assets/de7dc2fd-b4b3-49be-a6bc-03ad98c169c7)

Enable MISP feeds 
![image](https://github.com/user-attachments/assets/66771717-1c81-4051-b5c3-c9b8456b0845)
![image](https://github.com/user-attachments/assets/349bb8b9-9828-438b-b5a2-1bff7c593b41)
Click on the balck button with white arrow down, will see the Green box pop up
![image](https://github.com/user-attachments/assets/30981fc6-853b-4702-88a9-1a2a4df182d2)
Click on the Home button and make sure you have some events in, I have more than 237 alread
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
0 */6 * * * bash -c 'sudo -u www-data /var/www/MISP/app/Console/cake Server fetchFeed 1 all && sleep 300 && /home/user/misp-to-pihole.py'
```
![image](https://github.com/user-attachments/assets/52406925-d28c-4ec6-95ab-f6bc739ceafc)

Go chek if its in the Pihole WebGUI
![image](https://github.com/user-attachments/assets/7b236e33-86bb-4435-8c03-8f3857812ccb)

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

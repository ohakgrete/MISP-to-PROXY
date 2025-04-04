 # MISP + Pi-hole Installation Guide
 
 This README provides step-by-step instructions for installing both **MISP** (Malware Information Sharing Platform) and **Pi-hole** on a Debian-based system (tested on Debian 12). The process uses the official installation scripts from each project’s GitHub repository.
 
 ---
 
 ## Important
 
 - These scripts assume you have **sudo** or **root** privileges.  
 - MISP and Pi-hole each have their own dependencies; ensure your system is up-to-date before proceeding.  
 - If you plan to run both on the **same machine**, verify that there are no port conflicts (e.g., Pi-hole typically runs a DNS service and a web dashboard).  
 - Consult each project’s official documentation for more advanced configuration.
 
 ---
 
 ## Prerequisites
 
 ### Operating System
 - Ubuntu 24.04 LTS
 
 ### Run the install.sh - It will install MISP and then Pi-Hole
 ```bash
chmod +x install.sh
sudo ./install.sh
 ```
 
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

Go chek if its in the Pihole WebGUI
![image](https://github.com/user-attachments/assets/7b236e33-86bb-4435-8c03-8f3857812ccb)

 
 ## 5. References & Further Reading
 
 - **MISP Documentation**:  
   [https://github.com/MISP/MISP](https://github.com/MISP/MISP)
 - **Pi-hole Documentation**:  
   [https://github.com/pi-hole/pi-hole](https://github.com/pi-hole/pi-hole)
 - **Official MISP Debian 12 Install Script**:  
   [https://github.com/MISP/MISP/blob/2.5/INSTALL/INSTALL.debian12.sh](https://github.com/MISP/MISP/blob/2.5/INSTALL/INSTALL.debian12.sh)
 - **Pi-hole Basic Install Script**:  
   [https://github.com/pi-hole/pi-hole/blob/master/automated%20install/basic-install.sh](https://github.com/pi-hole/pi-hole/blob/master/automated%20install/basic-install.sh)
 ```

My notes and scripts for the Collegiate Cyber Defence Competition (CCDC).

basic_defend.sh

basic_defend.sh is the first script I've written myself. It does a fairly basic enumeration and hardening pass on the Ubuntu mail server that I defend in CCDC. It's deliberately simple and I'll be refining it as I go.

What it does

* Lists SUID and SGID binaries
* Shows the key Postfix settings (relaying, trusted networks, banner)
* Finds world-writable files
* Lists cron jobs, including every user’s crontab
* Shows open ports and the process behind each one
* Asks before turning on the firewall (ufw) and before locking down cron permissions

Usage

git clone https://github.com/YarrBlackism/Blackism_CCDC.git
cd Blackism_CCDC
sudo bash basic_defend.sh

Note: This is a very basic script. Read it before you run it and edit the firewall ports to match the services your team are scored on (i.e. saying yes blocks every port that isn't on the list).

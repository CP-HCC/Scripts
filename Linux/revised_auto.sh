#!bin/bash

(echo "Provide Root Password" && sudo echo "Thanks :)\n") || echo "Rude\n"

echo "Configuring Firewall: Deny Incoming, Allow Outgoing"
(sudo ufw default deny incoming && sudo ufw default allow outgoing && sudo ufw enable && echo "We are defended by a wall of fire\n") || echo "Uh.. The Fire hath been doused..\n"

#echo "Disabling Root SSH Login"
#sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.old
#sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/f' /etc/ssh/sshd_config
#echo "No more root SSH\n"

echo "Searching for johntheripper"
(sudo apt --purge john && echo "John has been ripped\n") || echo "John is nowhere to be found.."


echo "Things to check:"
echo "- Disable SSH Root Login"
echo "- Remove Guest Login"
echo "- Check All User Permissions"
echo "- Check If Any Users Need Added"
echo "- Read The README"
echo "- Check If Netcat is listening"
echo "- Set Update Policies"
echo "- Download And Install Updates"
echo "- Read The README Again, For Real This Time"







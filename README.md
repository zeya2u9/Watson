# Watson

This repository contains the code implementation of paper titled "Every Sherlock Needs a Watson: Practical Semi-Realtime Attack Elaboration System" accepted in 18th International Conference on Network and System Security (NSS). Watson is a modular attack elaboration framework which works in semi-realtime on the output of any learning based NIDS.

## Watson Design Details
<div align = "center">
  <img src="https://github.com/user-attachments/assets/cd75365b-e917-4d97-853c-911e48cb2fc8" width="750" height="320">
</div>


## Repository Structure
For each attack module, there is a respective folder with its logic code and other necessary files.

_Threat Class-I:_ It contains code for port scan classification.

_Threat Class-II:_ It contains code for SSH bruteforce attack detection.

_Threat Class-III:_ It contains two sub-folders for DNS flood (_dnsFlood_) and DNS amplification (_dnsAmplification_) attacks.



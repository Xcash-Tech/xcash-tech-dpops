# X-CASH Delegated Proof Of Privacy Stake (DPOPS)
 
X-CASH DPOPS is a variation of DPOS and DBFT. The key features of X-CASH DPOPS are:
 
* The top 100 delegates are elected as block verifiers.
* Reserve proof based voting/staking system, meaning the XCASH always stays in your wallet.
* No need to keep your wallet or computer online if your just staking towards a shared delegate.
* No need to keep your XCASH directly on the server if running a solo node, as you can use an empty wallet on the server and vote for yourself.
* A minimum of 2 million XCASH is needed to vote for a delegate.
 
* The election process is every block, meaning a new vote will get counted for the next block.
* No need to cancel a vote, as it will automatically get cancelled if you change your vote to a different delegate.
* No lockup times, the xcash always remains in your wallet and you can use them at any time, although moving them from your wallet will cancel your entire staking vote.
* No fees for voting, and you can revote or switch your vote as many times as you like.
 
* Using a variation of Delegated Byzantine Fault tolerance consensus where 67% consensus must be reached for a new block to be added to the network.
* DBFT allows for up to 33% of the elected block verifiers to stop working, and the system will still be able to produce a new block.
* Using Verifiable Random Functions to select the next block producer in the system. This allows for a random, but verifiable way of selecting the next block producer.
* Blocks can be verified in the XCASH Daemon with a detailed explanation of the reserve bytes in the block.
 
* Using a decentralized database system, to hold all of the voting data and reserve bytes data.
* The block format is to only store a hash of the contents of the reserve bytes data in the block, and store the actual reserve bytes data in the decentralized database, to reduce the extra size of the blockchain, while keeping all of the rounds data.
 
This program allows one to run a DPOPS node, a shared delegates website, and a delegates website.

**If you plan on running a [shared delegates website](https://github.com/X-CASH-official/XCASH_DPOPS_shared_delegates_website) or a [delegates website](https://github.com/X-CASH-official/XCASH_DPOPS_delegates_website), you will need to run the website on the same system as the DPOPS node**

**By running a DPOPS node (solo or shared) you will need the computer to be online and running at all times**


## Table of Contents  
[System Requirements](#system-requirements)  
[Dependencies](#dependencies)  
[Recommendations For the XCASH Wallet](#recommendations-for-the-xcash-wallet)  
[Installation Process](#installation-process)  
* [Installation Path](#installation-path)  
* [Install System Packages](#install-system-packages) 
* [Installing MongoDB From Binaries](#installing-mongodb-from-binaries)  
* [Building the MongoDB C Driver From Source](#building-the-mongodb-c-driver-from-source)  
* [Cloning the Repository](#cloning-the-repository)  
* [Build Instructions](#build-instructions)  

[How To Setup and Install the Systemd Files](#how-to-setup-and-install-the-systemd-files)  
* [MongoDB](#mongodb)  
* [XCASH Daemon](#xcash-daemon)  
* [XCASH Daemon Block Verifier](#xcash-daemon-block-verifier)  
* [XCASH Wallet](#xcash-wallet)
* [XCASH DPOPS](#xcash-dpops)
* [Firewall](#firewall)  

[How To Setup the Firewall](#how-to-setup-the-firewall)  
[How To Run Each Component](#how-to-run-each-component)  
[How To View Logs For Each Component](how-to-view-logs-for-each-component)  
[Running X-CASH Proof of stake test](#running-x-cash-proof-of-stake-test)  
[How to Use the XCASH DPOPS Wallet Commands](#how-to-use-the-xcash-dpops-wallet-commands)  
*  [How to Register a Delegate](#how-to-register-a-delegate)  
*  [How to Vote For a Delegate](#how-to-vote-for-a-delegate)  
*  [How to Update a Delegates Information](#how-to-update-a-delegates-information)  
*  [How to Remove a Delegate](#how-to-remove-a-delegate)  

### Appendix
[How to Setup a Domain Name Instead of an IP Address](#how-to-setup-a-domain-name-instead-of-an-ip-address)  
[How to Setup the Test](#how-to-setup-the-test)

 
## System Requirements
 
XCASH DPOPS will only run on a Linux/Unix OS at this time. We recommend installing this on a Ubuntu VPS/dedicated server (18.04) for the best compatibility.
 
**Minimum System Requirements:**  
Operating System: Ubuntu 18.04 (or higher)  
CPU: 4 threads  
RAM: 8GB  
Hard drive: 50GB  
Bandwidth Transfer: 500GB per month  
Bandwidth Speed: 30 Mbps
 
**Recommended System Requirements:**  
Operating System: Ubuntu 18.04 (or higher)  
CPU: 8 threads  
RAM: 16GB  
Hard drive: 100GB  
Bandwidth Transfer: 2TB per month  
Bandwidth Speed: 100 Mbps
 
 
## Dependencies
 
The following table summarizes the tools and libraries required to run XCASH DPOPS
 
| Dependencies                                 | Min. version  | Ubuntu package            |
| -------------------------------------------- | ------------- | ------------------------- |
| GCC                                          | 4.7.3         | `build-essential`         |
| CMake                                        | 3.0.0         | `cmake`                   |
| pkg-config                                   | any           | `pkg-config`              |
| OpenSSL                                      | any           | `libssl-dev`              |
| Git                                          | any           | `git`                     |
| MongoDB                                      | 4.0.3         |  install from binaries    |
| MongoDB C Driver (includes BSON libary)      | 1.13.1        |  build from source        |
| XCASH                                        | latest version         |  [download the latest release](https://github.com/X-CASH-official/X-CASH/releases) or [build from source](https://github.com/X-CASH-official/X-CASH#compiling-x-cash-from-source)       |
 
 
## Recommendations For the XCASH Wallet
It is recommended if you are going to run a XCASH DPOPS node, to not keep all of your XCASH on the server. The recommended way is to create an empty wallet and leave that on the server, to collect the block rewards, and then use your main wallet to vote for the new wallet that you created on the server.



## XCASH_DPOPS Parameters
```
--parameters - Show a list of all valid parameters

--test - Run the test to make sure the program is compatible with your system

--total_threads "total_threads" - The total threads to use.
If this parameter is not specified, the default is the number of threads the CPU has.

--delegates_website - Run the delegates website

--shared_delegates_website --fee "fee" --minimum_amount "minimum_amount" - Run the shared delegates website, with a fee of "fee" and a minimum amount of "minimum_amount"
The fee in a percentage (1 would equal 1 percent. You can use up to 6 decimal places.)
The minimum for a public_address to receive a payment (10000 etc. The minimum amount should be in regular units, not atomic units.)

--synchronize_database - Synchronize the database from a network data node.

--disable_synchronizing_databases_and_starting_timers - Disables synchronzing the databases and starting the timers. Used for testing.

--test_data_add - Add test data to the databases

--test_data_remove - Remove test data from the databases
```



## Installation Process

### Installation Path
It is recommend to install the XCASH_DPOPS folder, MongoDB and MongoDB C Driver in the home directory (`/home/$USER/`) or root directory (`/root/`) in a `Installed-Programs` folder
 
### Install System Packages
Make sure the systems packages list is up to date  
`sudo apt update`
 
Install the packages  
`sudo apt install build-essential cmake pkg-config libssl-dev git`
 
(Optionally) Install the packages for XCASH if you plan to [build XCASH from source](https://github.com/X-CASH-official/X-CASH#compiling-x-cash-from-source)
 
 
 
### Installing MongoDB From Binaries
 
Visit [https://www.mongodb.com/download-center/community](https://www.mongodb.com/download-center/community)
 
Then choose your OS, and make sure the version is the current version and the package is server. Then click on All version binaries. Now find the current version to download. You do not want the debug symbols or the rc version, just the regular current version.
 
Once you have downloaded the file move the file to a location where you want to keep the binaries, then run this set of commands 

**If you want to install MongoDB on a different hard drive then the hard drive your OS is installed on, make sure to change the path of the `/data/db`**
``` 
tar -xf mongodb-linux-x86_64-*.tgz
rm mongodb-linux-x86_64-*.tgz
sudo mkdir -p /data/db
sudo chmod 770 /data/db
sudo chown $USER /data/db
```
 
 
 
### Building the MongoDB C Driver From Source
 
Visit the official websites installation instructions at [http://mongoc.org/libmongoc/current/installing.html](http://mongoc.org/libmongoc/current/installing.html)
You will need to follow the instructions for [Building from a release tarball](http://mongoc.org/libmongoc/current/installing.html#building-from-a-release-tarball) or [Building from git](http://mongoc.org/libmongoc/current/installing.html#building-from-git) since you need the header files, not just the library files.
 
After you have built the MongoDB C driver from source, you will need to run  
`sudo ldconfig`
 
 
 
### Cloning the Repository
```
cd ~/Installed-Programs 
git clone https://github.com/X-CASH-official/XCASH_DPOPS.git
```
 
 
 
### Build Instructions
 
XCASH_DPOPS uses a Make file.
 
After cloning the repository, navigate to the folder  
`cd ~/Installed-Programs/XCASH_DPOPS`
 
Then use the make file to build the binary file  
`make clean ; make release`
 
 
 
## How To Setup and Install the Systemd Files

Edit the below systemd files to your paths

Copy all of the service files in the systemd folder to `/lib/systemd/system/`  
`cp -a ~/Installed-Programs/XCASH_DPOPS/scripts/systemd/* /lib/systemd/system/`

Reload systemd  
`systemctl daemon-reload`

Create a systemd PID folder  
`mkdir ~/Installed-Programs/systemdpid/`

Create a mongod pid file and a xcashd pid file
```
touch ~/Installed-Programs/systemdpid/mongod.pid
touch ~/Installed-Programs/systemdpid/xcash_daemon.pid
```


### MongoDB
This is the systemd file for MongoDB
```
[Unit]
Description=MongoDB Database Server
After=network.target

[Service]
Type=forking
User=root
Type=oneshot
RemainAfterExit=yes
PIDFile=/root/Installed-Programs/systemdpid/mongod.pid
ExecStart=/root/Installed-Programs/mongodb-linux-x86_64-ubuntu1804-4.2.0/bin/mongod --fork --syslog

LimitFSIZE=infinity
LimitCPU=infinity
LimitAS=infinity
LimitNOFILE=64000
LimitNPROC=64000
LimitMEMLOCK=infinity
TasksMax=infinity
TasksAccounting=false

[Install]
WantedBy=multi-user.target
```

You will need to change the **User** to the user of the system

You will need to change the **PIDFile** to the full path of the `mongod.pid` file

You will need to change the **ExecStart** to the full path of the `mongod` file

Reload systemd after you have made any changes to the systemd service files  
`systemctl daemon-reload`


### XCASH Daemon
This is the systemd file for XCASH Daemon
```
[Unit]
Description=XCASH Daemon systemd file
 
[Service]
Type=forking
User=root
PIDFile=/root/Installed-Programs/systemdpid/xcash_daemon.pid
ExecStart=/root/Installed-Programs/X-CASH/build/release/bin/xcashd --rpc-bind-ip 0.0.0.0 --rpc-bind-port 18281 --restricted-rpc --confirm-external-bind --detach --pidfile /root/Installed-Programs/systemdpid/xcash_daemon.pid
RuntimeMaxSec=15d
Restart=always
 
[Install]
WantedBy=multi-user.target
```

Make sure to leave the RuntimeMaxSec in the systemd service file, as the XCASH Daemon usually needs to restart after a while to prevent it from not synchronizing

You will need to change the **User** to the user of the system

You will need to change the **PIDFile** to the full path of the `xcash_daemon.pid` file

You will need to change the **ExecStart** to the full path of the `xcashd` file

Reload systemd after you have made any changes to the systemd service files  
`systemctl daemon-reload`



### XCASH Daemon Block Verifier
This is the systemd file for XCASH Daemon when you are a block verifier  
**Only run the XCASH Daemon service file, as the XCASH DPOPS program will determine if your a block verifier and start the correct systemd service file**
```
[Unit]
Description=XCASH Daemon Block Verifier systemd file
 
[Service]
Type=forking
User=root
PIDFile=/root/Installed-Programs/systemdpid/xcash_daemon.pid
ExecStart=/root/Installed-Programs/X-CASH/build/release/bin/xcashd --block-verifier --rpc-bind-ip 0.0.0.0 --rpc-bind-port 18281 --restricted-rpc --confirm-external-bind --detach --pidfile /root/Installed-Programs/systemdpid/xcash_daemon.pid
RuntimeMaxSec=15d
Restart=always
 
[Install]
WantedBy=multi-user.target
```

Make sure to leave the RuntimeMaxSec in the systemd service file, as the XCASH Daemon usually needs to restart after a while to prevent it from not synchronizing

You will need to change the **User** to the user of the system

You will need to change the **PIDFile** to the full path of the `xcash_daemon.pid` file

You will need to change the **ExecStart** to the full path of the `xcashd` file

Reload systemd after you have made any changes to the systemd service files  
`systemctl daemon-reload`



### XCASH Wallet
This is the systemd file for XCASH Wallet
```
[Unit]
Description=XCASH Wallet
 
[Service]
Type=simple
User=root
ExecStart=/root/Installed-Programs/X-CASH/build/release/bin/xcash-wallet-rpc --wallet-file /root/Installed-Programs/X-CASH/build/release/bin/WALLET_FILE_NAME --password PASSWORD --rpc-bind-port 18285 --confirm-external-bind --daemon-port 18281 --disable-rpc-login --trusted-daemon
Restart=always
 
[Install]
WantedBy=multi-user.target

```

You will need to change the **User** to the user of the system

You will need to change the **WALLET_FILE_NAME** with the name of your wallet file, and the **PASSWORD** with the password of your wallet file.

Reload systemd after you have made any changes to the systemd service files  
`systemctl daemon-reload`


### XCASH DPOPS
This is the systemd file for XCASH DPOPS
```
[Unit]
Description=XCASH DPOPS
 
[Service]
Type=simple
LimitNOFILE=64000
User=root
WorkingDirectory=/root/Installed-Programs/XCASH_DPOPS/
ExecStart=/root/Installed-Programs/XCASH_DPOPS/XCASH_DPOPS
Restart=always
 
[Install]
WantedBy=multi-user.target
```

The LimitNOFILE will allow the XCASH DPOPS program to utilize up to 64000 concurrent file descriptors instead of the default 4096 for a linux process. The actual XCASH DPOPS program is limited to only accept up to 1000 concurrent connections due to that DPOPS usage and shared delegates website or delegates website usage will not be that much at the start. This will help with DDOS at this time and the limits in the XCASH DPOPS program will be updated.

You will need to change the **User** to the user of the system

You will need to change the **ExecStart** to the full path of the `XCASH_DPOPS` file and add any startup flags if running a shared delegates website or a delegates website

To run the XCASH DPOPS node and the shared delegates website, add the flag `--shared_delegates_website`

To run the XCASH DPOPS node and the delegates website, add the flag `--delegates_website`

Reload systemd after you have made any changes to the systemd service files  
`systemctl daemon-reload`



### Firewall
This is the systemd file for firewall
```
[Unit]
Description=firewall
 
[Service]
Type=oneshot
RemainAfterExit=yes
User=root
ExecStart=/root/Installed-Programs/XCASH_DPOPS/scripts/firewall/firewall_script.sh
 
[Install]
WantedBy=multi-user.target
```

You will need to change the **User** to the user of the system

You will need to change the **ExecStart** to the full path of the `firewall_script.sh` file

Reload systemd after you have made any changes to the systemd service files  
`systemctl daemon-reload`



## How To Setup the Firewall
 
We will need to setup a firewall for our DPOPS node. The goal of settings up the firewall is to block any DDOS attacks. We will use IPtables for the firewall
 
The firewall is configured for a solo node setup. To configure the firewall for a shared delegates website or delegates website:
 
Open the firewall script  
`nano ~/Installed-Programs/XCASH_DPOPS/scripts/firewall/firewall_script.sh`
 
Uncomment these 3 lines (by removing the `#`) if running a shared delegates website or delegates website  
`# iptables -t filter -I INPUT -p tcp --syn --dport 80 -m connlimit --connlimit-above 100 --connlimit-mask 32 -j DROP`
 
`# iptables -A INPUT -p tcp --dport 80 -j ACCEPT`
 
`# iptables -A PREROUTING -t nat -p tcp --dport 80 -j REDIRECT --to-ports 18283`
 
If you want to run the shared delegates website or delegates website using HTTPS, you will need to install a webserver like nginx and configure it.
 
Now we need to run the firewall script and activate it  
```
chmod +x ~/Installed-Programs/XCASH_DPOPS/scripts/firewall/firewall_script.sh
~/Installed-Programs/XCASH_DPOPS/scripts/firewall/firewall_script.sh
iptables-save > /etc/network/iptables.up.rules
iptables-apply -t 60
```
 
You should then open another connection to the server to make sure it worked and did not lock you out. Then press y to confirm the changes for the firewall.

Now we need to enable the firewall systemd service file to run this script after a restart  
`systemctl enable firewall`
 
 
 
 
## How To Run Each Component
To start a systemd service  
`systemctl start name_of_service_file_without.service`

To stop a systemd service  
`systemctl stop name_of_service_file_without.service`

To restart a systemd service  
`systemctl restart name_of_service_file_without.service`

To check the status of a systemd service  
`systemctl status name_of_service_file_without.service`

For example

To start XCASH DPOPS service  
`systemctl start XCASH_DPOPS`

To stop XCASH DPOPS service  
`systemctl stop XCASH_DPOPS`

To restart XCASH DPOPS service  
`systemctl restart XCASH_DPOPS`

To check the status of XCASH DPOPS service  
`systemctl status XCASH_DPOPS`



## How To View Logs For Each Component
To view the logs for any service file. you can run  
`journalctl --unit=name_of_service_file_without.service`

To view only the last 100 lines of the log file, you can run  
`journalctl --unit=name_of_service_file_without.service -n 100 --output cat`

To view live logging of XCASH DPOPS, you can run  
`journalctl --unit=XCASH_DPOPS --follow -n 100 --output cat`
 
 
 
## Running X-CASH Proof of stake test
It is recomeneded to run the X-CASH Proof of stake test before you run the main program. The test will ensure that your system is compatbile, and that you have setup your system correctly.
 
To run the X-CASH Proof of stake test, make sure to have already started the XCASH Daemon, XCASH Wallet and MongoDB systemd services, and to have stopped the XCASH DPOPS systemd service if it was already running. 

Navigate to the folder that contains the binary  
Rebuild the binary in debug mode  
`make clean ; make debug`

Then run the binary  
`./XCASH_DPOPS --test`
 
The test will return the number of passed and failed test on the bottom of the console. The failed test need to be 0 before you run the node. If the output is not showing 0 for failed test, then you need to scroll through the testing output and find what test failed (It will be red instead of green). If this is a system compatibility test, then you will need to fix the system. If this is a core test that has failed, then you need to possibly rebuild, or contact us with your OS version, and we can look into it.



## How to Use the XCASH DPOPS Wallet Commands



### How to Register a Delegate
Make sure to stop the XCASH Wallet service if it is running  
`systemctl stop XCASH_Wallet`

Open the wallet file in the `xcash-wallet-cli`

Once the wallet is fully synchronized run the following:  
`delegate_register delegate_name delegate_IP_address`

Replace delegate_name with the name that you want to name your delegate

Replace delegate_IP_address with your VPS/dedicated servers IP Address or a domain name (View the setup below)



### How to Vote For a Delegate
Make sure to stop the XCASH Wallet service if it is running  
`systemctl stop XCASH_Wallet`

Open the wallet file in the `xcash-wallet-cli`

Once the wallet is fully synchronized run the following:  
`vote delegates_public_address | delegates_name`

Replace delegates_public_address | delegates_name with the delegates public address or delegates name




### How to Update a Delegates Information
Make sure to stop the XCASH Wallet service if it is running  
`systemctl stop XCASH_Wallet`

Open the wallet file in the `xcash-wallet-cli`

Once the wallet is fully synchronized run the following:  
`delegate_update item value`

Replace item with the item you want to update. The list of valid items are:  
```
IP_address
about
website
team
pool_mode
fee_structure
server_settings
```
Replace value with the updated information



### How to Remove a Delegate
Make sure to stop the XCASH Wallet service if it is running  
`systemctl stop XCASH_Wallet`

Open the wallet file in the `xcash-wallet-cli`

Once the wallet is fully synchronized run the following:  
`delegate_remove`


# Appendix



## How to Setup a Domain Name Instead of an IP Address
The XCASH DPOPS system needs a IP Address when registering a delegate to be able to let other delegates know where to send messages to. One can instead setup a domain name (**without the www.**) and register this instead of an IP address. The possible benefits of using a domain name over an IP address could be:

* One can change IP's from their domain page if they change servers instead of having to update that info in the DPOPS database.
* It would probably be more recognizable if there was a problem, since in the XCASH_DPOPS logs and the XCASH_Daemon logs it will print the source and destination of messages.

To Setup a domain instead of an IP address, go to the domain registrar you have purchased the domain name from. Add an A record to the domain. Each domain registrar is going to be a little different, so you will want to check if they have an official article on how to add an A record.

Now you need to setup the reverse DNS as well. Go to the hosting dashboard of the place where you are renting the server. Not all hosting companies let you change the reverse DNS, so you might not be able to change the reverse DNS. Navigate to the server your are renting. At this point their should be something that says modify the reverse DNS or something similar. Change it to the domain name you used in the first step.

At this point you can now register the domain name (**without the www.**) to the XCASH DPOPS system.




## How to Setup the Test
Create a `XCASH_DPOPS_Test` folder in the `Installed-Programs` folder

Make sure you have installed the packages to [build XCASH from source](https://github.com/X-CASH-official/X-CASH#compiling-x-cash-from-source)

Copy the X-CASH and XCASH_DPOPS folders from the `Installed-Programs` folder to the `XCASH_DPOPS_Test` folder  
```
cp -a ~/Installed-Programs/X-CASH ~/Installed-Programs/XCASH_DPOPS_Test/X-CASH 
cp -a ~/Installed-Programs/XCASH_DPOPS ~/Installed-Programs/XCASH_DPOPS_Test/XCASH_DPOPS
```

Navigate to the X-CASH folder and change the branch to `xcash_proof_of_stake` and then rebuild the binary  
```
cd ~/Installed-Programs/XCASH_DPOPS_Test/X-CASH
git checkout xcash_proof_of_stake
make clean ; make release -j `nproc`
```

Create a wallet file for the wallet you are going to register. **Make sure this is an empty wallet.** This should be a different wallet then the wallet you plan to register for the official DPOPS, to keep your wallets privacy until the official DPOPS  
```
cd ~/Installed-Programs/XCASH_DPOPS_Test/X-CASH/build/release/bin
./xcash-wallet-cli
```

Register your wallet with the XCASH team to get **XCASH_DPOPS_TEST XCASH** sent to the wallet

Create a `XCASH_DPOPS_Blockchain_Test` folder in the `Installed-Programs`
```
cd ~/Installed-Programs
mkdir XCASH_DPOPS_Blockchain_Test
```

Stop all of the systemd services  
```
systemctl stop MongoDB
systemctl stop XCASH_Daemon
systemctl stop XCASH_Wallet
systemctl stop XCASH_DPOPS
```

If you already have the mainnet blockchain synchronized, skip this step and follow the "Create test blockchain from mainnet blockchain"

Download the XCASH test blockchain from our blockchain download server. 
```
cd ~/Installed-Programs/XCASH_DPOPS_Test/
wget http://147.135.68.247:8000/XCASH_DPOPS_Blockchain_Test
```

Import the XCASH_DPOPS_Blockchain and save the blockchain in the `XCASH_DPOPS_Blockchain_Test` folder  
```
/root/Installed-Programs/XCASH_DPOPS_Test/X-CASH/build/release/bin/xcash-blockchain-import --input-file /root/Installed-Programs/XCASH_DPOPS_Test/XCASH_DPOPS_Blockchain --data-dir /root/Installed-Programs/XCASH_DPOPS_Test/XCASH_DPOPS_Blockchain_Test
```

Create test blockchain from mainnet blockchain. Skip this step if you already imported the blockchain. Copy the .X-CASH folder at ~/X.CASH to the XCASH_DPOPS_Test folder  
`cp -a ~/.X-CASH /root/Installed-Programs/XCASH_DPOPS_Test/XCASH_DPOPS_Blockchain_Test`

Remove all of the blocks up to 440875  
`/root/Installed-Programs/XCASH_DPOPS_Test/X-CASH/build/release/bin/xcash-blockchain-import --pop-blocks NUMBER_OF_BLOCKS_TO_REMOVE	`

After the blockchain has been imported configure the `XCASH_Daemon`, `XCASH_Daemon_Block_Verifier`, `XCASH_Wallet` and `XCASH_DPOPS` systemd service files for the XCASH_DPOPS test. You should just have to add `/XCASH_DPOPS_Test` to every full path in the systemd service files.

Reload systemd after you have made any changes to the systemd service files  
`systemctl daemon-reload`

start all of the systemd services  
```
systemctl start MongoDB
systemctl start XCASH_Daemon
systemctl start XCASH_Wallet
systemctl start XCASH_DPOPS
```

Check the block height of the XCASH_DPOPS_Blockchain_Test  
```
curl -X POST http://127.0.0.1:18281/json_rpc -d '{"jsonrpc":"2.0","id":"0","method":"get_block_count"}' -H 'Content-Type: application/json'
```

The block height should be 440875

Check if your wallet has a any XCASH_DPOS_TEST XCASH in it  
```
curl -X POST http://localhost:18285/json_rpc -d '{"jsonrpc":"2.0","id":"0","method":"get_balance"}' -H 'Content-Type: application/json'
```

Register the wallet into the DPOPS system  
Replace `DELEGATE_NAME` with a delegate name  
Replace `DELEGATE_IP_ADDRESS` with the servers public IP address, or a domain name
```
curl -X POST http://localhost:18285/json_rpc -d '{"jsonrpc":"2.0","id":"0","method":"delegate_register","params":{"delegate_name":"DELEGATE_NAME","delegate_IP_address":"DELEGATE_IP_ADDRESS"}}' -H 'Content-Type: application/json'
```

Vote for the wallet  
Replace `DELEGATES_PUBLIC_ADDRESS` with the wallets public address
```
curl -X POST http://localhost:18285/json_rpc -d '{"jsonrpc":"2.0","id":"0","method":"vote","params":{"delegate_public_address":"DELEGATES_PUBLIC_ADDRESS"}' -H 'Content-Type: application/json'
```

Open the log files for XCASH_DPOPS  
`journalctl --unit=XCASH_DPOPS --follow -n 100 --output cat`
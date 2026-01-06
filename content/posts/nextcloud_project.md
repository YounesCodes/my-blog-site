---
title: "How I built my own home cloud storage with NextCloud"
layout: ""
date: 2026-01-02
---

In this article, I will guide you through building your own home cloud storage using Nextcloud.

![captionless image](https://miro.medium.com/v2/resize:fit:1000/format:webp/1*cSTTYmVep5ezLNfD1Fuz4A.jpeg)

> **Note :** This method is by no means the only way to set up a home storage, this article documents how I did it.

Before we start, we need a couple things:

*   A spare PC/laptop (server)
*   Your main PC/laptop (for configuration)
*   A domain name (optional, only if you want remote access outside your home network)



# **1. Install and configure Ubuntu server**
-------------------------------------------

**Ubuntu Server official install documentation :** [https://ubuntu.com/tutorials/install-ubuntu-server#1-overview](https://ubuntu.com/tutorials/install-ubuntu-server#1-overview)

After installation, configure Internet access :

*   **Wi-Fi :** See right below for the setup.
*   **Ethernet** : Plug in an ethernet cable if you have your router nearby (I don’t), in most cases, you won’t need to set up anything else.

Additionally, you will need to set a static local IPv4 address for your server, here is a guide demonstrating how :

[https://gal.vin/posts/2023/ubuntu-static-ip/](https://gal.vin/posts/2023/ubuntu-static-ip/) (the yaml config in the guide is for an ethernet connection).

**If you want to connect to a Wi-Fi network :**

I shared a sample config file that I worked with in the github repo of this project : [https://github.com/YounesCodes/nextcloud-home-server](https://github.com/YounesCodes/nextcloud-home-server)

After you follow the steps in the first link and replace values in config file accordingly, you will have set up both the connection to Wi-Fi AND assigning a static IP to your server, two birds with one stone, cool :).

> Run an ifconfig/ip a to check if static IP is assigned, and ping google.com for example to check for connectivity.

Run this command to update packages :

```
sudo apt update && sudo apt upgrade
```

To manage the server efficiently, connect via **ssh** from your main laptop. This allows you to copy-paste commands directly and follow the guide side-by-side.

Before moving to Nextcloud setup, we must configure the firewall. On a fresh Ubuntu server install, the firewall is usually inactive. We need to define allow rules before turning it on.

Run these commands in order:

```
# ssh - port 22
sudo ufw allow ssh
# local web traffic - ports 80 and 443
sudo ufw allow http
sudo ufw allow https
# enabling firewall
sudo ufw enable
```

> **Note:** You must open these ports now so your main laptop can reach the Nextcloud web interface for the initial setup. If you later decide to configure the **Cloudflare Tunnel** for remote access, you can choose to close ports 80 and 443 for maximum security, ssh must remain accessible on the local network. Do not expose it publicly unless required.



# **2. Install Nextcloud**
-------------------------

I chose a snap installation (easiest to set up), you can go for that or the docker image option. I will only cover the snap installation process.

Run this command to install nextcloud :

```
sudo snap install nextcloud
```

After it finishes, nextcloud service will start automatically.

Next, visit the IP address of your server on your main laptop’s browser, the first time, you will be prompted to enter an admin _username_ and _password_ before Nextcloud is initialized.

It may take a while depending on the device performance and internet speed.

It should look something like this :

![captionless image](https://miro.medium.com/v2/resize:fit:794/format:webp/1*BqN0v84jONJCmbJky8efaA.png)

Nextcloud will continue installing and configuring for some time (again depends on your device/internet), then it will prompt you to install recommended apps (calendar, contacts…).

I recommend you skip on that unless you’ll need them for your use case, storage is a native functionality of NextCloud anyways, so no need for additional apps.

> You can always install them later if you wish.

Once that the setup is done, you will be redirected to the dashboard, it will look something like this :

![captionless image](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*4UV5iUn_RxdNtOimiY1SFw.png)

Let’s upload a file to test out the service, from the files section, click on new → Upload files, then choose the file you wish to upload :

![captionless image](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*7U985mjiRjKPQ-C_tDdxTQ.png)

And voila, you have successfully uploaded your first file on your local storage!

Congratulations, you now have a fully operational local storage server, if you wish to stop here without setting up remote access, that is totally fine.

If not, let’s continue.



# **3. Remote access**
---------------------

In this section, we will configure a Cloudflare Tunnel to make our home server accessible from outside our network.

First step is to acquire a domain, there are many sites where you can purchase one for very cheap, I got one for $1/year on [Namecheap](https://namecheap.com), so I recommend that.

Next, go to [https://dash.cloudflare.com/](https://dash.cloudflare.com/), create an account, add your domain via the account home dashboard by clicking on ‘_Onboard a domain_’:

![captionless image](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*Sj5TneJqAxvzgtPKyjzGng.png)

Enter your domain name, leave everything else on default and click continue :

![captionless image](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*--K6KBYMraXo3x3x7ym10Q.png)

Select the free plan :

![captionless image](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*-IDsBpLjMWD72jxdBBxDmw.png)

Finally, skip adding DNS records by clicking on ‘_Continue to activation_’ :

![captionless image](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*iSOcSxFaJmJDkciSHO57EA.png)

You will be redirected to the last step of the setup, where you will have to copy the 2 nameservers Cloudflare provided, and add them to your domain custom DNS nameservers :

![captionless image](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*CccBmzx8zm7kakUfnwuagA.png)

If you used Namecheap to purchase a domain, go to your dashboard, click on ‘_Manage_’ next to your domain, then scroll down until you see nameservers and change it to ‘_custom DNS_’ then paste the Cloudflare nameservers (Step 2's _DNSSEC_ is disabled by default on Namecheap) :

![captionless image](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*LhpnyNI0yXRDZ20wqjXXhA.png)

After some time, Cloudflare will verify that you successfully added the nameservers and will activate the domain.

With that, Cloudflare will become the authoritative DNS, and traffic can be proxied and protected.

Before moving on to the tunnel, ensure that Cloudflare SSL/TLS mode is set to Full, if not click on Configure and change it (**Full** is required because Nextcloud Snap uses a self-signed certificate, **Full (Strict)** would require installing a valid origin certificate) :

![captionless image](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*RE4lqgjuaAbJLQSlGXpEbA.png)

Now, let’s set up the tunnel, here is an overview of the architecture :

```
Internet --> Cloudflare --> Tunnel --> localhost --> Nextcloud
```

With this architecture, we will have no NAT or firewall issues.

Run these commands to install Cloudflare Tunnel client on the ubuntu server (ssh connection recommended) :

```
sudo apt update
sudo apt install cloudflared
```

Next, authenticate using :

```
cloudflared tunnel login
```

It will give you an URL to log in and download a certificate, copy and paste it on your browser :

![captionless image](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*r4NNS7VpKsSfxwZtj0-_VA.png)

In the browser page, authorize the tunnel for the domain you just configured :

![captionless image](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*nURSfAh9-fL1k3xpODk5hQ.png)![captionless image](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*QZ5AxiVR5mXu8H7NqHq0Cg.png)

If successful, you get this message :

![captionless image](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*TXOHuBn8hbmRj7ezBFN8Bg.png)

Now, let’s create the tunnel via the following command on the server :

```
cloudflared tunnel create nextcloud
```

Save the JSON credential file path that is outputted from this command, we will need it shortly after.

Enable DNS binding (domain → tunnel) by running the following :

```
cloudflared tunnel route dns nextcloud YOUR-DOMAIN.com
```

Next, we have to create a tunnel YAML config file :

```
sudo mkdir /etc/cloudflared # create directory if it doesn't exist
sudo nano /etc/cloudflared/config.yml
```

Paste the following config and make sure you replace credentials file path and hostname with your own :

```
tunnel: nextcloud
credentials-file: <YOUR-CREDENTIALS-FILE-PATH>
ingress:
  - hostname: YOUR-DOMAIN.com
    service: http://localhost
  - service: http_status:404
```

Following that, we must install cloudflared as a system service to have a persistent tunnel that auto-starts on boot :

```
sudo cloudflared service install
# then restart it
sudo systemctl restart cloudflared
```

Finally, onto the last touches, open the config.php for nextcloud :

```
sudo nano /var/snap/nextcloud/current/nextcloud/config/config.php
```

Find ‘trusted_domains’ and change its value to this :

```php
// ...
'trusted_domains' =>
  array (
    0 => 'localhost',
    1 => 'YOUR-DOMAIN.com'
  ),
// ...
```

Below it add the following :

```php
// ...
'trusted_proxies' =>
  array (
    0 => '127.0.0.1',
  ),
  'overwritehost' => 'YOUR-DOMAIN.com',
  'overwriteprotocol' => 'https',
  'overwrite.cli.url' => 'https://YOUR-DOMAIN.com',
// ...
```

> Make sure to replace ‘YOUR-DOMAIN.com’ with your own.

Restart Nextcloud :

```
sudo snap restart nextcloud
```

And you are done!

You should be able to access your server now via the browser by typing in your domain.

Congratulations! You have made your first step into homelabbing, you successfully implemented a **secure remote access architecture,** I hope you will enjoy it!


# **4. What’s Next?**
----------------

Now that your cloud is live, here are a few more things you can explore:

*   **Mobile Sync:** Download the Nextcloud app on your phone to upload your mobile data.
*   **Expansion:** Look into Nextcloud apps to discover all the features it has to offer, we barely scratched the surface. The only limit is your creativity.

Building a homelab is a journey of continuous learning. If you ran into issues or made cool modifications/additions, feel free to share them in the responses below!

**Happy hosting!**
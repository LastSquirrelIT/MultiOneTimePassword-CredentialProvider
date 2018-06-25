**This Repository is not maintained anymore. Please head over to this great fork: https://github.com/multiOTP/multiOTPCredentialProvider**

Hi, this is Dominik from Last Squirrel IT. Here I'm providing my Credential Provider (CP) for Microsoft Windows-based systems.

MultiOneTimePassword Credential Provider
========================================

The *MultiOneTimePassword Credential Provider* (mOTP-CP) aims to improve the overall security of the Windows logon process by adding an authenticator. The additional authenticator is "Something That You Have" and consists of the validation of an one-time password (OTP).

The CP's base behaves like the built-in *Password Credential Provider*, so that Windows' default authentication ("Something That You Know", username and password) and enhanced authentication ("Something That You Have", one-time password, token, etc.) are indepent from each other, but both may be required to authenticate a user.

You can use *software or hardware tokens* like *mobileOTP* and *Google Authenticator* for Windows logon, but can also *receive one-time passwords over the air by SMS* or have a *scratch passwords list* for offline authentication.


----


Screenshots
-----------

The [screenshots](http://tinyurl.com/mOTP-Screenshots) are hosted on Google Drive.


Download and Install
--------------------

To download the Windows Installer packages (.msi) please head over [to our releases section here on GitHub](https://github.com/LastSquirrelIT/MultiOneTimePassword-CredentialProvider/releases). Just extract the archive, follow the instructions on [this wiki page to install and configure *multiOTP.exe*](https://github.com/LastSquirrelIT/MultiOneTimePassword-CredentialProvider/wiki/MultiOTP) and install the provider's MSI Installer package.

*Please note that future downloads will be available on our website - which will be published soon - too.*


----


Support this Software and Donate
--------------------------------

The credential provider will stay **free for private use**. This project takes a measurable amount of my spare time - including support and help. You like this piece of software? I appreciate if you support the development with buying me a beer - or two. Further a donation will make you feel better - for sure :)


**Donate via *PayPal.*** [![Donate via PayPal][4]][3]
<!--
Or send a micro donation via *Flattr.* [![Flattr this][2]][1] ***NOT WORKING NOW***
//-->

*Just click the logo of your preferred service above. Thank you! You are awesome! :)*

[1]: http://flattr.com/thing/
[2]: http://api.flattr.com/button/button-static-50x60.png
[3]: https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=P4L7UBSP57WW4
[4]: https://www.paypalobjects.com/webstatic/de_DE/i/de-pp-logo-100px.png


----


The Credential Provider
=======================

*mOTP-CP* requires *multiOTP.exe* to be available on the target machine. You can download *multiOTP.exe* at http://www.multiotp.net .

You have to add user accounts to *multiOTP.exe*, before installing *mOTP-CP*. See [MultiOTP](https://github.com/LastSquirrelIT/MultiOneTimePassword-CredentialProvider/wiki/MultiOTP) in the project Wiki-pages for a descriptive How-To on installing, configuring and testing *multiOTP.exe*.

***multiOTP.exe* features:**
 - Full client/server support
 - Emergency scratch passwords list
 - SMS code sending
 - Automatic caching of token definitions used on the machine
 - One-click installation in about 10 seconds
 - Many many more...

**Requirements:**
 - mobileOTP, Google Authenticator or the like (OATH/HOTP, OATH/TOTP or mobileOTP compatible token generator)
 - Windows Vista/7/2008/8/2012 both 32 and 64 bits
 - Administrator privileges
 - *multiOTP.exe* (http://www.multiotp.net) (read our Wiki for [MultiOTP](https://github.com/LastSquirrelIT/MultiOneTimePassword-CredentialProvider/wiki/MultiOTP))
 - Configured user account(s) in *multiOTP.exe* (use your Windows account name!)

 
----


Client-Server Operation
-----------------------

This functionality including a cache feature (for laptops) is available in cooperation with SysCo and included into *multiOTP.exe*. [The new release](ttp://www.multiotp.net/website/index.php?language=en) also includes SMS-authentication, QRcode generation and scratch passwords.

Just download the latest version of mOTP-CP and configure *multiOTP.exe* for network access and synchronization. See [this wiki-page](https://github.com/LastSquirrelIT/MultiOneTimePassword-CredentialProvider/wiki/MultiOTPClientServerSetUp) for client-server installation instructions.


----


General information
===================
Testing your installation
-------------------------
To verify that *mOTP-CP* works for you, you should deselect to install the software as default provider during installation. If it works, just re-install *mOTP-CP* with the option checked. If it fails, feel free to contact me or file an issue. Nobody's perfect  :)

Account locking / OTPs out of sync
----------------------------------

*mOTP-CP* will add a virtual user account to your system called *"Resync OTP"*.
In that case you can not logon to your account using OTPs, they may be out of sync. You may resynchronize them before logging in again.

By default multiotp.exe from SysCo locks accounts after *six* failed authentication requests. After that happened you may resychronize your OTPs and logon again.

Error: You need to be Administrator!
------------------------------------

Whenever you encounter this error, you are possibly on a Windows Server or Enterprise system. It depends on the way how Windows elevates privileges during an MSI install. It seems that this behaviour is more strict on Server and Enterprise systems.

For the time being just **run the setup and (re-)configuration from an elevated command prompt**.

Windows Safe Mode
-----------------

By default, Windows **does not load** custom credential providers (like *mOTP-CP*) in safe mode.
If you really want to know how to enable *mOTP-CP* in safe mode, reading our UseInSafeMode wiki page may help you.

Unattended/Mass deployment of the provider
------------------------------------------

To mass deploy *mOTP-CP* [see the unattended installation wiki-page](https://github.com/LastSquirrelIT/MultiOneTimePassword-CredentialProvider/wiki/UnattendedInstallation) for the setup-file parameters.


----


Project information
===================
Issues and Bugs
---------------
 - If there are bugs or issues, please mind [filing a bug report](https://github.com/LastSquirrelIT/MultiOneTimePassword-CredentialProvider/issues) using the issue tracker.

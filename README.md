# hlock
Blocks SQL Injection, bad bots and bad IPs

Join our global network to protect your pages from hackers. 

- central server for bad ips,bots and injection filter
- reports to central server
- every webproject, which uses hlock, helps other projects to get protected
- totally free to use
- internet security should be for free

This project should help us developer to protect our PHP projects from hacking. Bad IPs will be reported to central server 
and hlock updates hisself with a current list of bad ips, bots and SQL injection rules.
Be part of the network and help us to get the web safer!
 
This version is compatible with keimeno CMS, but can easly changed to be compatible with Wordpress, Joomla and Typo3.
Just change the path to files and ensure the HLOCK_ROOT is successfully set.
 
How to implement?
add in your project index.php:
  require (CMS_ROOT . 'includes/hlock.class.php');
  hlock::run();
 
The keimenbo CMS includes the hlock project is already in the core.

from fabric.api import env, settings
from fabric.operations import run, put, sudo

import random
import logging, traceback
import sys


env.warn_only = True
#env.hosts = ['icinga.lab']


#env.hosts = ['10.204.82.15']

#e2e hosts
#env.hosts = ['10.204.82.15', '10.204.82.16', '10.204.100.208', '10.204.100.209', '10.204.82.23', '10.204.100.25', '10.204.100.26', '10.204.82.21', '10.204.100.33', '10.204.82.22', '10.204.100.31', '10.204.100.32', '10.204.82.250', '10.204.101.11', '10.204.101.12', '10.204.100.20', '10.204.100.21', '10.204.100.35', '10.204.100.36', '10.204.100.37', '10.204.100.63', '10.204.100.22', '10.204.100.11', '10.204.100.13', '10.204.100.14', '10.204.82.11', '10.204.98.71', '10.204.82.27']


env.hosts = ['10.204.82.15', '10.204.82.16', '10.204.100.208', '10.204.100.209', '10.204.82.23', '10.204.100.25', '10.204.100.26', '10.204.82.21', '10.204.100.33', '10.204.82.22', '10.204.100.31', '10.204.100.32', '10.204.82.250', '10.204.101.11', '10.204.101.12', '10.204.100.20', '10.204.100.21', '10.204.100.35', '10.204.100.36', '10.204.100.37', '10.204.100.22', '10.204.100.11', '10.204.100.13', '10.204.100.14', '10.204.82.11', '10.204.98.71', '10.204.82.27']

print "\nHosts that will be used in script %r " % (env.hosts)

x = 1

def title(desc):
  global x
  if x == 1:
    print "\n", desc, "\n"
    x -= 1
  else:
    pass





def test_sudoers():
  with open("lab_hosts_ips", "a") as f:
		hostname = run('hostname ')
		ifconfig = run('/sbin/ifconfig | grep 10.204 -B 1')
		profile = run('ls -l /etc/profile')
		#whoami = sudo('whoami')
    #out = run("ls -l /etc/sudoers | awk '{ print $1, $9}' ")
    #admin = sudo("grep "^admin" /etc/sudoers")
    #admin_keys = run("cat ~/.ssh/authorized_keys | wc -l")
		f.write("Hostname => %s\n%s\nProfile => %s\n---------------\n" % (hostname, ifconfig, profile))


def add_key():
	with open("key_file", "a"):
		run("mkdir /home/admin/.ssh/backup/ -p ; mv /home/admin/.ssh/authorized_keys /home/admin/.ssh/backup/authorized_keys")
		put("team_keys", "/tmp/team_keys")
		run("cat /tmp/team_keys >> /home/admin/.ssh/authorized_keys")
		run("rm /tmp/team_keys")
		run("restorecon -R /home/admin/.ssh/")
		run("chmod 0600 /home/admin/.ssh/authorized_keys")
		run("chmod 0700 /home/admin/.ssh")



def sudoers():
	with open("sudoers", "a") as f:
		#sudo("chmod u+w /etc/sudoers")
		#sudo("chmod u+w ; sed -i -e 's#^%Admin.*$##g' /etc/sudoers -e '/^root.*ALL$/a %Administrators     ALL=(ALL)       NOPASSWD:ALL'  /etc/sudoers; chmod u-w /etc/sudoers")
		put("sudoers.sh", "/tmp/sudoers.sh")
		sudo("/bin/bash /tmp/sudoers.sh")
		run("rm /tmp/sudoers.sh")
		#sudo("chmod u-w /etc/sudoers")


def set_prompt():
	desc = "This will set prompt on hosts"
	title(desc)
  
	put("cms_prompt", "/tmp/cms_prompt")
	sudo("cat /tmp/cms_prompt >> /etc/profile")
	run("rm /tmp/cms_prompt")


def test_package():
	with open("rpm_file", "a") as f:
		hostname = run("hostname")
		rpm = run("rpm -qa | grep -w 'psacct\|sysstat'")
		#yum = run("yum search psacct sysstat")

		f.write("Hostname => %s\nInstalled => %s\n---------------\n" % (hostname, rpm))


def install_package():
	with open("yum_file", "a") as f:
		desc = "This will install rpm on system"
		title(desc)
		hostname = run("hostname")
		yum = sudo("yum -y install lsof")

		f.write("Hostname => %s\nInstalled => %s\n---------------\n" % (hostname, yum))




def user_mod(user_name, user_param):
  with open("user_pass","a") as pass_file:
    #print (mypw)
    usermod= sudo("usermod -aG %s  %s" % (user_param, user_name))
    #user = sudo("useradd -u %s -g 100 -G %s  %s" % (user_uid, user_group, user_name))
    #passwd = sudo("echo %s | passwd $1 --stdin %s" % (mypw, user_name))
    #passwd = sudo("echo `openssl rand -base64 8` | passwd $1 --stdin %s" % (user_name))
    #pass_file.write("user => %s pass => %s\n" % (user, passwd))


def group_add(group_name, gid):
  with open("group_file","a") as pass_file:
    usermod= sudo("groupadd -g %s %s" % (gid, group_name))



def host_check():
	with open("host_file", "a") as f:
		hostname = run("hostname")
		ip = run("/sbin/ifconfig")
		#ssh_allowed_groups = run("grep Allow /etc/ssh/sshd_config")
		#sudoers = sudo("grep %Administrators /etc/sudoers")
		#selinux = sudo("getenforce")
		#f.write("Hostname => %s\nssh_allowed_groups => %s\nip => %s\n--------------\n" % (hostname, ssh_allowed_groups, ip))
		f.write("Hostname => %s\nip => \n%s\n--------------\n" % (hostname, ip))
		#f.write("Hostname => %s\nsudoers => %s\n--------------\n" % (hostname, sudoers))
		#f.write("Hostname => %s\nselinux => %s\n--------------\n" % (hostname, selinux))


def test_user(user_name):
  run("id %s" % (user_name))
	

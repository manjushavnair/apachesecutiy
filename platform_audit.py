#!/usr/bin/python2
import sys,os

import sys
import urllib.request
from urllib.error import HTTPError,URLError

from urllib.request import urlopen
import configparser as ConfigParser

from optparse import OptionParser
from urllib.error  import   HTTPError, URLError
import string
import getopt
import spwd,pwd
from optparse import OptionParser
import re
import rpm
import collections 
import stat
import io
import yum
from xml.dom.minidom import parse, parseString
from pwd import getpwuid
from grp import getgrgid
import stat 
from datetime import date, datetime, timedelta
from time import mktime
from urllib.request import urlopen, ProxyHandler, build_opener, install_opener
import gzip, mailbox, email, os, sys, re, subprocess, time, errno, platform
# Ignore deprecation warning for use with popen2
import warnings
with warnings.catch_warnings():
	warnings.filterwarnings("ignore",category=DeprecationWarning)
	import popen2


################################
#          Dev info            #
################################
#                              #
#  Plz comment all  fixes ;)   #
################################

# init RPM
ts = rpm.TransactionSet()

# filtering os.peopen depricated warnings
from warnings import filterwarnings
filterwarnings('ignore')

# Internal vars
DEBUG=0;
LISTCHECKS=0;
WHITELIST=[];
BLACKLIST=[];
REPORT='short';
PROXY=""

checks = [];
######################################################
#             Configs/rules for checks               #
######################################################
#
# WhiteList: users with password
UserWithPassword_wl=["root", "0wnag3"];

# Apaches modules that we don't whant to see, and that we want to see
Modules_wl=[["info_module","status_module","proxy_ftp_module","proxy_http_module","proxy_module","proxy_balancer_module","proxy_connect_module","imap_module","cgi_module","suexec_module","autoindex_module","userdir_module","cern_meta_module","dav_module","mod_include"],["security2_module"]]

#Tomcat path (if empty - get from /proc and RPM)
TomcatPath=""

# TCP/IP configuration in /etc/sysctl for IPv4
sysctl_ipv4_checklist = {
    "\n\s*net.ipv4.ip_forward\s*=\s*0\s*\n" :
        { 'value' : '0' , 'message' : "Disable IP Packet forwarding."}, \
    "\n\s*net.ipv4.conf.all.send_redirects\s*=\s*0\s*\n" :
        { 'value' : '0' , 'message' : "Disable ICMP redirects on *all* interfaces."},\
	"\n\s*net.ipv4.conf.default.send_redirects\s*=\s*0\s*\n" :
        { 'value' : '0' , 'message' :  "Disable ICMP redirects on the *default* interface. "}, \
    "\n\s*net.ipv4.conf.default.accept_source_route\s*=\s*0\s*\n" :
        { 'value' : '0' , 'message' : "Disable accepting IPv4 source route information."},\
    "\n\s*net.ipv4.conf.all.accept_redirects\s*=\s*0\s*\n" :
        { 'value' : '0' , 'message' : "Disable accepting IPv4 redirects on all interafces."} ,\
	"\n\s*net.ipv4.conf.default.accept_redirects\s*=\s*0\s*\n" :
        { 'value' : '0' , 'message' :  "Disable accepting IPv4 redirects on default interafce."} ,\
    "\n\s*net.ipv4.conf.all.secure_redirects\s*=\s*0\s*\n" :
        { 'value' : '0' , 'message' :  "Disable IPv4 accepting secure_redirects on all interfaces."} ,\
    "\n\s*net.ipv4.conf.default.secure_redirects\s*=\s*0\s*\n":
        { 'value' : '0' , 'message' : "Disable accepting secure_redirects on default interface."},\
    "\n\s*net.ipv4.conf.all.log_martians\s*=\s*1\s*\n" :
        { 'value' : '1' , 'message' : "Enable IPv4 log_martians."},\
    "\n\s*net.ipv4.icmp_echo_ignore_broadcasts\s*=\s*1\s*\n" :
        { 'value' : '1' , 'message' : "Ignore ICMP echo (ping) broadcasts."},\
    "\n\s*net.ipv4.icmp_ignore_bogus_error_responses\s*=\s*1\s*\n" :
        { 'value' : '1' , 'message' : "Ignore ICMP bogus error messages."},\
    "\n\s*net.ipv4.tcp_syncookies\s*=\s*1\s*\n" :
            { 'value' : '1' , 'message' : "TCP SYN cookies is not enabled."},\
    "\n\s*net.ipv4.conf.all.rp_filter\s*=\s*1\s*\n" :
        { 'value' : '1' , 'message' : "IPv4 conf rp_filter is not set."},\
    "\n\s*net.ipv4.conf.default.rp_filter\s*=\s*1\s*\n" :
        { 'value' : '1' , 'message' : "IPv4 conf rp_filter is not set."}
    }


# TCP/IP configuration in /etc/sysctl for IPv6
sysctl_ipv6_checklist = {
		"\n\s*net.ipv6.conf.default.router_solicitations\s*=\s*0\s*\n" :
            { 'value' : '0' , 'message' : "IPv6 ----------- Change it by setting "},\
		"\n\s*net.ipv6.conf.default.accept_ra_rtr_pref\s*=\s*0\s*\n":
            { 'value' : '0' , 'message' : "IPv6 ----------- Change it by setting "},\
		"\n\s*net.ipv6.conf.default.accept_ra_pinfo\s*=\s*0\s*\n":
            { 'value' : '0' , 'message' : "IPv6 ----------- Change it by setting "},\
		"\n\s*net.ipv6.conf.default.accept_ra_defrtr\s*=\s*0\s*\n":
            { 'value' : '0' , 'message' : "IPv6 ----------- Change it by setting "},\
		"\n\s*net.ipv6.conf.default.autoconf\s*=\s*0\s*\n":
            { 'value' : '0' , 'message' : "IPv6 ----------- Change it by setting "},\
		"\n\s*net.ipv6.conf.default.dad_transmits\s*=\s*0\s*\n":
            { 'value' : '0' , 'message' : "IPv6 ----------- Change it by setting "},\
		"\n\s*net.ipv6.conf.default.max_addresses\s*=\s*1\s*\n":
            { 'value' : '1' , 'message' : "Maxglobal unicast IPv6 addresses can be assigned to each interface is not set to 1 Change it by setting "}
    }

##########################################################

# Internal stuff
def dprint(lvl, msg):
  if (lvl <= DEBUG): # FIX. Was:  'if (lvl > DEBUG):'. Changed by  Reason: deafult should be non debug mode.
    print (msg);

##### generic class
class GenericCheck:
  check_id = 0x00000000;
  whitelisted = [];
  alerts = [];
  run = 1;
  issue = 0;
  def __init__(self,wl=[]):
    dprint (1, "GENERIC init "+str(wl));
    self.whitelisted = wl;
  def check_prereq(self):
    dprint (1, "GENERIC prereq");
    self.run=1;
  def run_check(self):
    dprint (1, "GENERIC run_check");
  def isrunnable(self):
    dprint (1, "GENERIC isrunnable");
    return self.run;
  def alert(self,details):
    dprint (1, "GENERIC alert");
    for entry in self.whitelisted:
      if entry == details:
        return
    self.alerts.append(details);
    self.issue=1;
  def disable(self):
    self.run=0;
  def enable(self):
    self.run=1;
  def report(self,type='short'):
    dprint (1, "GENERIC print_report");
    if self.isrunnable():
      self.print_report(type);
    else:
      print (self.__class__.__name__+" DISABLED!")

  def print_report(self,type='short'):
    dprint (1, "GENERIC print_report");
    if type != 'short':
     print (self.__class__.__name__+" Report:")
     if len(self.alerts) > 0:
      for alert in self.alerts:
        print (alert)
     else:
       print ("No Issues Detected")
    else:
      if len(self.alerts) > 0:
        print (self.__class__.__name__+" : ALERT "+str(len(self.alerts))+" ISSUES DETECTED");
      else:
        print (self.__class__.__name__+" : No ISSUES");

##################################################################
#                          CHECKS                                #
##################################################################
# 


# Allowed CentOS releases and their release dates
# Release dates are used to speed up downloads 
# by starting only from the release date.
# Get the release dates from:
# http://en.wikipedia.org/wiki/CentOS#Release_history

class PatchCheck(GenericCheck):
	check_id = 0x0F000001;
	alerts = [];
	centos_release_dates = {}
	centos_release_dates[6] = [2011,7]
	centos_release_dates[5] = [2007,4]
	critical=""
	important=""
	moderate=""
	low=""
	# How many days old AMI can be used?
	AMI_MAX_LIFETIME=180

	# Compile regular expressions to be used below
	# TODO: figure out why do we need SPACES and SPACE separately
	REGEX_SLASH = re.compile(r"/")
	REGEX_SPACE = re.compile(r" ")
	REGEX_SPACES = re.compile(r'\s+')
	REGEX_RISK = re.compile(r".*(Critical|Important|Moderate|Low).*")
	REGEX_RISK_INFO = re.compile(r".*(https?:\/\/rhn.redhat.com/errata/RH[SB]A.+\.html).*")
	# http://www.rpm.org/max-rpm/ch-rpm-file-format.html
	# The format is: pkgname-version-release.arch.rpm
	REGEX_RPMFILENAME = re.compile(r"(.*)-([\d\.]+)-(.*)\.(i[3456]86|x86_64|ia64|s390|s390x|alpha|noarch|src)\.rpm")
	def check_prereq(self):
		dprint (1, self.__class__.__name__+" prereq "+str(os.geteuid()));
		self.run=1;
		
		if PROXY:
			proxy_server = {'http':PROXY}
			proxy_handler = ProxyHandler(proxy_server)
			opener = build_opener(proxy_handler)
			install_opener(opener)
			dprint (1, "Using Proxy " + str(PROXY));
		url = "http://lists.centos.org/pipermail/centos-announce/"
		try:
			resp = urlopen(url)
		except:
			dprint(2,"No internet, sorry")
			self.run=0;
			
			
	def run_check(self):
		# If no cmd line options, then download updates and check the system.
		
		
		_out_filename = "/tmp/patchlist-centos" + platform.dist()[1][0] + date.today().strftime("-%Y%b%d.list")
			
		self.download_updates(int(platform.dist()[1].split(".")[0]),_out_filename)
			
		dprint (2,"---")
			
		try:
			FILE_IN = open(_out_filename,'r')
		except IOError as (ex_no, ex_str):
			dprint(1,"IO Error %(num)s: %(msg)s. Unable to read input file." % {'num':ex_no, 'msg':ex_str})
			return

		self.check_patches(FILE_IN)
			
		FILE_IN.close()
		os.remove(_out_filename)
			
				
		footer_notes = "NOTE: This program can only detect missing patches on CentOS packages from standard CentOS repos or mirrors. " 
		footer_notes += "If you have packages from 3rd party repos like rpmforge or epel, or have installed packages using .tar.gz, compiled from source, or "
		footer_notes += "installed an .rpm downloaded from non-CentOS repo, then this script will not find missing patches."
		
		dprint(2, "---\n" + footer_notes + "\n---")
    

	def download_updates(self,os_ver,_out_filename):
		security_patches = set()
		_begin_year = self.centos_release_dates[os_ver][0]
		_begin_mon = self.centos_release_dates[os_ver][1]
		
		try:
			FILE_OUT = open(_out_filename,"w")
		except IOError as (ex_no,ex_str):
			self.fatal_error("IO Error %(num)s. %(str)s. Unable to write to output file." % {'num':ex_no, 'msg':ex_str})
		
		for year in range(_begin_year,date.today().year+1):
			#print ("Processing " + str(year) +", month:"),
			sys.stdout.flush()
			
			for mon in range (1,13):            
				if (year == _begin_year) and (mon < _begin_mon):
					continue
				
				if (year == date.today().year) and (mon > date.today().month):
					break
				
				current_date = date(year,mon,1)
				filename = current_date.strftime("%Y-%B.txt.gz")
				url = "http://lists.centos.org/pipermail/centos-announce/" + filename

				try:
					_remote_file = urlopen(url)
					#if (_remote_file.code == 200):
					#	print (mon),
					
					sys.stdout.flush()
					
					_local_file = open("/tmp/" + filename, 'w')
					_local_file.write(_remote_file.read())
					_local_file.close()
					_FILE_GZ = gzip.open ('/tmp/'+filename, 'rb')
					_file_content = _FILE_GZ.read()
					_FILE_TXT = open("/tmp/" + current_date.strftime("%Y-%B.txt"), 'w')
					_FILE_TXT.writelines(_file_content)
				except HTTPError as err:
					if (err.getcode() == 404):
						dprint(2, (str(mon)+"(NOFILE_GOT_HTTP_404)")),
					else:
						self.fatal_error("Unknown HTTPError occurred: " + err.strerror)
				except IOError as err:
					if "CRC check failed" in str(err):
						# Sometimes proxy server keeps a partial or corrupt file in cache, and sends that to us.
						# Dont know how to force the proxy to re-download the file from remote host.
						_msg = "CRC check failed. Probably an issue with file download or proxy? "
						_msg += "If the download fails with this error for particular month even after retries, then "
						_msg += "the proxy might be caching a partial or bad file. Try a different proxy."
						self.fatal_error(_msg) 
					else:
						self.fatal_error("An unhandled IO Error occurred: %(msg)s" % {'msg':err}) 


				except:
					dprint(2, "Unknown error occurred.") 
					dprint (2, sys.exc_info()[0])
					sys.exit(1)
				
				if (mon == 12) or ((year == date.today().year) and (mon == date.today().month)):
					dprint(2, "Download done.") 
				sys.stdout.flush()
				
				_mbox_filename = "/tmp/" + current_date.strftime("%Y-%B.txt")
				try:
					mb = mailbox.mbox(_mbox_filename)
				except AttributeError:
					mb = mailbox.PortableUnixMailbox(file(_mbox_filename),factory=email.message_from_file)
				except IOError as e:
					dprint(2, "ERROR"+ e)
				# Parse each message in gunzipped mbox files
				for message in mb:
					# Skip non-CESA messages and messages with empty subject
					if (not message['subject']) or ((not 'CESA' in message['subject']) and (not 'CEBA' in message['subject'])):
						continue # Hope that CentOS always uses a non-empty subject line for CESA
					target_os = "CentOS " + str(os_ver)
					# Tracking security updates only for target os.
					# Assumption: Subject line always contains os version info.
					if not target_os in message['subject']:
						continue
						
					# There was atleast one multipart email in centos-announce mailing list. So handle multipart msgs.
					if message.is_multipart():
						for part in message.get_payload():
								if part.get_content_maintype() == 'text':
									_body += part.get_payload()
					elif message.get_content_maintype() == 'text':
						_body = message.get_payload()
					
					_risk_info = ""
					
					
					if( self.REGEX_RISK.search(message['subject'])):
						_risk = self.REGEX_RISK.search(message['subject']).group(1)
					elif( 'CEBA' in message['subject'] ):
					  _risk = 'Bug'
					
					for line in _body.split("\n"):
						if (self.REGEX_RISK_INFO.search(line)):
							_risk_info += self.REGEX_RISK_INFO.search(line).group(1)
						
						if self.REGEX_RPMFILENAME.search(line):
							if self.REGEX_SPACE.search(line):                        
								rpm_entry = str(line.split(" ")[-1])
							elif self.REGEX_SLASH.search(line):
								rpm_entry = str(line.split("/")[-1])
							else:
								rpm_entry = line
							
							_pkg_name = self.REGEX_RPMFILENAME.search(rpm_entry).group(1) + "." + self.REGEX_RPMFILENAME.search(rpm_entry).group(4)
							_pkg_ver = self.REGEX_RPMFILENAME.search(rpm_entry).group(2) + "-" + self.REGEX_RPMFILENAME.search(rpm_entry).group(3)
												
							security_patches.add(_pkg_name + "|" + _pkg_ver + "|" + _risk + "|" + _risk_info)
									
				_FILE_GZ.close()
				_FILE_TXT.close()
				try:
					os.remove("/tmp/" + filename)
					os.remove("/tmp/" + current_date.strftime("%Y-%B.txt"))
				except OSError as e:
					if (e.errno != errno.ENOENT):
						# This is not 'No such file or directory error'
						self.fatal_error( "Unknown error occurred while deleting temp files: " + e.strerror)
				
		for entry in sorted(security_patches):
			FILE_OUT.write(entry + "\n")
		
		FILE_OUT.close()
		sys.stdout.flush()
		
	def compare_versions(self,installed_ver, patch_ver):
		"""Compares two CentOS version strings, and returns True if patch_ver is greater.
		Otherwise returns False."""
		ver1 = installed_ver.replace('-','.')
		ver1 = ver1.replace('_','.')
		ver2 = patch_ver.replace('-','.')
		ver2 = ver2.replace('_','.')
		installed_ver_list = ver1.split('.')
		patch_ver_list = ver2.split('.')

		mapped = map(None, installed_ver_list, patch_ver_list)
		
		# Expected result of version compare is that 2.2 > 2.07. 
		# Direct int compare of minor versions will lead to 07 > 2 in the above example.
		# So the comparison should use .07 and .2 for anything except major version.
		major_version = False;
		
		# a pkg version info consists of major, minor and several revision numbers.
		# It can also contain alphabets. Now comparing each position in the version tuples.
		for sub_ver in mapped:
			
			# The first iteration deals with the major version.
			major_version = True;
			
			if sub_ver[0] is None:
				# Looks like installed_ver_list has less number of sub-ver items than patch_ver_list.
				return True
			
			if sub_ver[1] is None:
				return False
			
			try:
				if major_version:
					inst_sub_ver = int(sub_ver[0])
					patch_sub_ver = int(sub_ver[1])
				else:
					inst_sub_ver = "." + int(sub_ver[0])
					patch_sub_ver = "." + int(sub_ver[1])
					
			except ValueError as err:
				continue
					
			if inst_sub_ver > patch_sub_ver:
				return False
			elif inst_sub_ver < patch_sub_ver:
				return True
				
		return False

	def check_patches(self,FILE_IN):
		# Get the updated patchlist into a dict
		patched_ver = {}
		endLine="\n--------------------------------------------------------------------------------"
		self.check_amiversion()
		
		for line in FILE_IN:
			package_name = line.split('|')[0]
			patch_info = line.split('|')[1:]
			if not patched_ver.has_key(package_name):
			  patched_ver[package_name] = []
			patched_ver[package_name].append(patch_info)  
		
		pkg_all = " "
		for pkg_name in patched_ver.keys():
			pkg_all += pkg_name + " "
		
		# yum sometimes adds newlines in its output which messes up this parsing. So we try repoquery first.    
		cmd = "repoquery -C --installed --queryformat=\"%{name}.%{arch}|%{version}-%{release} %{version}-%{release}\" " + pkg_all    
		(status,out) = subprocess.getstatusoutput(cmd)
		if (status != 0):
			# repoquery is present in yum-utils package, and may not be installed by default on CentOS 5.
			# if installed in CentOS 5.x, it may not have --installed option.
			cmd = "yum -C list installed " + pkg_all
			(status,out) = subprocess.getstatusoutput(cmd)
			
		if (status != 0):
			FILE_IN.close()
			self.fatal_error("yum/repoquery command returned error. The output from yum/repoquery is:\n" + out)
		
		installed = out.split("\n")
		# installed is now a list of strings of format: pkgname    ver   @repo
		
		# Get rid of the first two lines of yum output
		if 'Loaded plugins' in installed[0]:
			installed.pop(0)
		if 'Installed Packages' in installed[0]:
			installed.pop(0)
		elif 'No matching Packages':
			# The (all) package(s) we queried for is/are not installed.
			installed.pop(0)
		
		yum_cmd = "/usr/bin/yum update"
		#pkgs_to_update = ""
		
		for line in installed:
			# remove white space from yum output and use | as the delimiter instead.
			entry = self.REGEX_SPACES.sub('|', line)
			current_pkg = entry.split('|')[0]
			current_ver = entry.split('|')[1]

			if ":" in current_ver:
				# the ver info from yum list installed is of format epoch:ver. Extract the ver alone.
				current_ver = current_ver.split(':')[1] 
			
			# compare patched_ver to current_ver and report
			for pkg_name in patched_ver.keys():
				if pkg_name != current_pkg:
					continue				
				
				for patch in patched_ver[pkg_name]:
				  if self.compare_versions(current_ver, patch[0]):
					strmsg = "\t" + pkg_name + " " + current_ver 
					strmsg += " Update: " + patch[0]
					strmsg += " URL: " + patch[2].rstrip()
					if patch[1] == "Critical":                   # Sorted by RISKlevel (added by Alexey)
						self.critical+=strmsg+"\n"
					elif patch[1] == "Important":
						self.important+=strmsg+"\n"
					elif patch[1] == "Moderate":
						self.moderate+=strmsg+"\n"
					else:
						self.low+=strmsg+"\n"
					dprint(2,strmsg+"\n")	
					#pkgs_to_update += " " + pkg_name
		

		if self.critical:
			self.alert("# CRITICAL_MISSED\n"+self.critical+endLine)
		if self.important:
			self.alert("# IMPORTANT_MISSED\n"+self.important+endLine)
		if self.moderate:
			self.alert("# MODERATE_MISSED\n"+self.moderate+endLine)
		if self.low:
			self.alert("# LOW_MISSED\n"+self.low+endLine)
			
		#if pkgs_to_update:
		#	print "\n---\nTo install only these packages and avoid installing other updates, run:"
		#	print yum_cmd + pkgs_to_update
			
		#	if "kernel" in pkgs_to_update:
		#		_msg = "\n---\nNOTE: The script reports missing patches on other installed kernels, " 
		#		print _msg + "even if the presently running kernel is fully patched. Uninstall unwanted kernel packages."
		#else:
		#	print "No pending security updates were found." 

	def check_amiversion(self):
		ami_file = "/etc/centos-release"
		if (os.path.isfile(ami_file)):
			AMI_FILE = open(ami_file,'r')
			for line in AMI_FILE:
				# Format is centos-6-(x86_64|i386)-mmddyyy-(instance|ebs)-(trunk|qa|release)
				_ami_date = date.fromtimestamp(mktime(time.strptime(line.split("-")[3],"%m%d%Y")))
				_today = date.today()
				_diff = _today - _ami_date 
				if (_diff.days > self.AMI_MAX_LIFETIME ):
					_msg = "WARNING:  AMI used in this system is " + str(_diff.days) + " days old. "
					_msg += "You should switch to a latest  AMI as soon as possible."
					print _msg + "\n---"

	def fatal_error(self,msg):
		dprint(1, msg)
		sys.exit(1) #hmmm.... dont'like it (TODO)

    

# Apache checker
#
# Check config files for:
# 	1)modules
# 	2)banner
# 	3)owner
#	4)log level
#	5)directories options (indexes/)
#
#  TODO: many things, "include" for an example
#

class TomcatConfigCheck(GenericCheck):
	check_id = 0x0A000002;
	alerts = [];
	defaultPath=""
	tomcatVer=6
	
	def getText(self,nodelist):
		rc = []
		for node in nodelist:
			if node.nodeType == node.TEXT_NODE:
				rc.append(node.data)
		return ''.join(rc)
	
	def __init__(self,defaultPath=TomcatPath):
		self.defaultPath=defaultPath
	def check_prereq(self):
		dprint (1, self.__class__.__name__+" prereq "+str(os.geteuid()));
		if os.geteuid() != 0:
			dprint (1, "ERROR, UID ne 0")
			self.run=0
			return
		if self.defaultPath:
			if not os.path.exists(self.defaultPath):
				dprint (1, "ERROR, can't find HOME dir at "+self.defaultPath)
				self.run=0
				return
			else:
				self.run=1
				return
		else:	
		
			MATCH_PID = r".*-Dcatalina\.base=('|\"|)(.*)('|\"|)-Dcatalina.*" 
			pids= [pid for pid in os.listdir('/proc') if pid.isdigit()]
			for pid in pids:
				line=open(os.path.join('/proc', pid, 'cmdline'), 'rb').read()
				match=re.match(MATCH_PID,line)
				if match:
					self.defaultPath=str(match.group(2))[:-1]
					self.run=1
					
			if	not self.defaultPath:	
				if (ts.dbMatch( 'name', 'tomcat5')):
					mi = ts.dbMatch( 'name', 'tomcat5')
					self.tomcatVer=5
					self.defaultPath=mi.next().fiFromHeader()[24] ## Very bad style jsut "luck"... need to fix or test more
				elif (ts.dbMatch( 'name', 'tomcat6')):
					mi = ts.dbMatch( 'name', 'tomcat6')
					self.tomcatVer=6
					self.defaultPath=mi.next().fiFromHeader()[24] ## Very bad style jsut "luck"... need to fix or test more
				elif (ts.dbMatch( 'name', 'tomcat7')):
					mi = ts.dbMatch( 'name', 'tomcat7')
					self.tomcatVer=7
					self.defaultPath=mi.next().fiFromHeader()[24] ## Very bad style jsut "luck"... need to fix or test more
				else:
					self.run=0
					return
			#print self.defaultPath
			if not os.path.exists(self.defaultPath):
				dprint (1, "ERROR, can't find DEFAULT HOME dir at "+self.defaultPath)
				self.run=0
				return
			else:
				self.tomcatVer=6
				self.run=1
				return
		

	def run_check(self):
		dprint (1, self.__class__.__name__+" run_check ");
		#Stage 0.
		catalinaHome=self.defaultPath
		dprint (2,"\n### Starting Tomcat hardening ... \n\nHome dir: "+catalinaHome+" ")
	##-------------
		troubleId=0;
		endLine="\n--------------------------------------------------------------------------------"
		
		#dirs=["","/conf","/logs","/webapps"]

		#### Owner...
		#dprint (2,"#Checking owner...\n")

		#for dir in dirs:
		#	error=""
		#	warning=""
		#	chkDir=catalinaHome+dir
		#	user=getpwuid(os.stat(chkDir).st_uid).pw_name
		#	group=getgrgid(os.stat(chkDir).st_gid).gr_name
		#	if(user!='tomcat'):
		#		error=error+"\n\t\tSET OWNER USER to 'tomcat'!"
		#	if(group!='tomcat'):
		#		error=error+"\n\t\tSET OWNER GROUP to 'tomcat'!"
		#	if error!="":
		#		troubleId+=1;
		#		warning=warning+"TOMCAT_WARNING ("+str(troubleId)+") "
		#	self.alert("\t "+warning+chkDir+"\t --> u: "+user+"  g: "+group+" "+error+endLine)
			
		#### Rights...
		dprint (2, "\n#Checking rights...\n")

		#conf
		if os.path.exists(catalinaHome+"/conf"):
			fileList = os.listdir(catalinaHome+"/conf")
			error=""
			for file in fileList:
				#print "# "+dirConf+file+" found!"
				if(stat.S_IMODE(os.stat(catalinaHome+"/conf/"+file).st_mode)!=256):
					error+="\t\t"+catalinaHome+"/conf/"+file+"\t\t\t---> current bits: "+oct(stat.S_IMODE(os.stat(catalinaHome+"/conf/"+file).st_mode))+" need to be set: 0400!\n"
			if error!="":
				troubleId+=1
				warning="TOMCAT_WARNING ("+str(troubleId)+") You have wrong permissions on files ("+catalinaHome+"/conf/):"
				self.alert(warning+"\n"+error+endLine)

		#logs
		if os.path.exists(catalinaHome+"/logs"):
			fileList = os.listdir(catalinaHome+"/logs")
			error=""
			for file in fileList:
				#print "# "+dirConf+file+" found!"
				if(stat.S_IMODE(os.stat(catalinaHome+"/logs/"+file).st_mode)!=192):
					error+="\t\t"+catalinaHome+"/logs/"+file+"\t\t\t---> current bits: "+oct(stat.S_IMODE(os.stat(catalinaHome+"/logs/"+file).st_mode))+" need to be set: 0300!\n"
			if error!="":
				troubleId+=1
				warning="TOMCAT_WARNING("+str(troubleId)+") You have wrong permissions on files ("+catalinaHome+"/logs/):"
				self.alert( warning+"\n"+error+endLine)
				
		#### webapps!
		dprint (2,"#Default apps...\n")

		defaultApps=['sample','samples', 'host-manager', 'manager', 'balancer', 'jsp-examples', 'servlet-examples', 'tomcat-docs', 'webdav','test','tests']
		#
		manager=0
		#

		error=""
		#1
		if os.path.exists(catalinaHome+"/webapps"):
			fileList = os.listdir(catalinaHome+"/webapps")
			for file in fileList:
				if file in defaultApps:
					error+="\t\t"+catalinaHome+"/webapps/"+file+"\t\t\t--->Remove it, if not needed!\n"
					if file=="host-manager" or file=="manager":
						manager=1

		#2
		if os.path.exists(catalinaHome+"/server/webapps"):
			fileList = os.listdir(catalinaHome+"/server/webapps")
			for file in fileList:
				if file in defaultApps:
					error+="\t\t"+catalinaHome+"/server/webapps/"+file+"\t\t\t--->Remove it, if not needed!\n"
					if file=="host-manager" or file=="manager":
						manager=1
				
		if error!="":
			troubleId+=1
			warning="TOMCAT_WARNING ("+str(troubleId)+") Check if this apps needed (remove defaults: samples, host-manager, manager, balancer, \n\tjsp-examples, servlet-examples, tomcat-docs, webdav):"
			self.alert(warning+"\n"+error+endLine)
			
		#### Manager
		dprint (2,"#Manager conf...\n")
		error=""
		if os.path.exists(catalinaHome+"/conf/Catalina/localhost/host-manager.xml"):
			error+="\t\t"+catalinaHome+"/conf/Catalina/localhost/host-manager.xml\t\t\t--->Remove it, if not needed! \n\t\t\t\t\t\t\t(if you are keeping the manager application, do not remove this)\n"
		if os.path.exists(catalinaHome+"/conf/Catalina/localhost/manager.xml"):
			error+="\t\t"+catalinaHome+"/conf/Catalina/localhost/manager.xml\t\t\t--->Remove it, if not needed! \n\t\t\t\t\t\t\t(if you are keeping the manager application, do not remove this)\n"
		if error!="":
			troubleId+=1
			warning="TOMCAT_WARNING ("+str(troubleId)+") Check if manager is needed (Note that it can be useful to keep the manager webapp installed if you need the ability to redeploy without restarting Tomcat.):"
			self.alert(warning+"\n"+error+endLine)
			
		#### serve index pages when a welcome file is not present
		dprint (2, "#Index...\n")
		error=""
		webXML=catalinaHome+"/conf/web.xml"
		if os.path.exists(webXML):
			xml = parse(webXML)
			for paramX in xml.getElementsByTagName("servlet"):
				if self.getText((paramX.getElementsByTagName("servlet-name")[0]).childNodes)=="default":
					for param in paramX.getElementsByTagName("init-param"):
						if self.getText((param.getElementsByTagName("param-name")[0]).childNodes)=="listings" and not re.match("^[\n\s]*false[\n\s]*$",self.getText(param.getElementsByTagName("param-value")[0].childNodes),re.IGNORECASE):
							error="\t\tIn "+webXML+": "+self.getText((param.getElementsByTagName("param-value")[0]).childNodes)+"\n\t\t\t\t\tset it to 'false' like:\n\t\t\t\t<init-param>\n\t\t\t\t  <param-name>listings</param-name>\n\t\t\t\t  <param-value>false</param-value>  <!-- make sure this is false -->\n\t\t\t\t</init-param>\n\n"

			if error!="":
				troubleId+=1
				warning="TOMCAT_WARNING ("+str(troubleId)+") Servlet is configured  to serve index pages when a welcome file is not present!"
				self.alert(warning+"\n"+error+endLine)

			#### 
			dprint (2, "#Error...\n")

			error="\t\tIn "+webXML+" define error-pages.  Place the following within the web-app tag (after the welcome-file-list tag is fine):\n\t\t\t<error-page>\n\t\t\t        <exception-type>java.lang.Throwable</exception-type>\n\t\t\t        <location>error.jsp</location>\n\t\t\t</error-page>\n\n\t\tThe following solution is not ideal as it produces a blank page \n\t\tbecause Tomcat cannot find the file specified, but without a better solution this, \n\t\tat least, achieves the desired result. A well configured web application will override this \n\t\tdefault in CATALINA_HOME/webapps/APP_NAME/WEB-INF/web.xml \n\t\tso it won't cause problems."

			if (len(xml.getElementsByTagName("error-page"))>0):
				for page in xml.getElementsByTagName("error-page"):
					if(len(page.getElementsByTagName("location"))>0):
						error=""

			if error!="":
				troubleId+=1
				warning="TOMCAT_WARNING ("+str(troubleId)+") Replace default error page (default is stacktrace) by adding the following into CATALINA_HOME/conf/web.xml. \n\tThe default error page shows a full stacktrace which is a disclosure of sensitive information.\n"
				self.alert( warning+"\n"+error+endLine)
			
		####
		dprint (2, "#Server...\n")
		error=""
		dprint (2,"\n\tParsing /conf/server.xml...")
		serverXML=catalinaHome+"/conf/server.xml"
		if os.path.exists(serverXML):
			xml = parse(serverXML)
			if len(xml.getElementsByTagName("Server")):
				dprint (2, "\tShutdown port is "+xml.getElementsByTagName("Server")[0].attributes["port"].value+" and word is "+xml.getElementsByTagName("Server")[0].attributes["shutdown"].value)
				secretword=xml.getElementsByTagName("Server")[0].attributes["shutdown"].value
				if (re.match(r"^\s*\d+\s*$",xml.getElementsByTagName("Server")[0].attributes["port"].value)):
					if bool((not re.match(r".*[_\~\!\@\#\$\%\^\&\*\(\)\?\!\?\;\:\?\\\/\{\[\]\}].*",secretword) or len(secretword)<9) and (int(xml.getElementsByTagName("Server")[0].attributes["port"].value)>0)) :
						error="\n\t\tword: "+xml.getElementsByTagName("Server")[0].attributes["shutdown"].value+" port: "+xml.getElementsByTagName("Server")[0].attributes["port"].value+"\n\t\tHINT: Try to use word with lenght>8 and use symbol, like _ or !\n\t\tBe sure that this port firewaled or disabled (-1 value)!"
						troubleId+=1
						warning="TOMCAT_WARNING ("+str(troubleId)+") Shutdown word is not good."
						self.alert(warning+"\n"+error+endLine)
				else:
					if bool((not re.match(r".*[_\~\!\@\#\$\%\^\&\*\(\)\?\!\?\;\:\?\\\/\{\[\]\}].*",secretword))):
						error="\n\t\tword: "+xml.getElementsByTagName("Server")[0].attributes["shutdown"].value+" port: "+xml.getElementsByTagName("Server")[0].attributes["port"].value+"\n\t\tHINT: Try to use word with lenght>8 and use symbol, like _ or !\n\t\tBe sure that this port firewaled or disabled (-1 value)!"
						troubleId+=1
						warning="TOMCAT_WARNING ("+str(troubleId)+") Shutdown word is not good. (check port number!)"
						self.alert(warning+"\n"+error+endLine)

		####
		dprint (2, "\n#Manager...\n") 

		if not manager:
			dprint (2, "\tINFO: Manager app is removed, no tests here!")
		else:
			dprint (2, "\tINFO: Manager app is present, start tests...")
			error=""
			dprint (2, "\n\tParsing /conf/tomcat-users.xml...")
			serverXML=catalinaHome+"/conf/tomcat-users.xml"
			if os.path.exists(serverXML):
				xml = parse(serverXML)
				if len(xml.getElementsByTagName("tomcat-users")):
					users=xml.getElementsByTagName("tomcat-users")[0].getElementsByTagName("user")
					if len(users)>0:
						for user in users:
							val=""
							part=""
							valList=user.attributes.keys()
							if("username" in valList):
								val="username"
								part="manager"
							elif("name" in valList):
								val="name"
								part="host-manager"
							if val:
								nm=user.attributes[val].value
								secretword=user.attributes["password"].value
								if secretword=="tomcat":
									error="\t\tChange password! It is very dangerous to use default one!"
									troubleId+=1
									warning="TOMCAT_WARNING ("+str(troubleId)+") Default password for "+part+": user="+nm+", pass="+secretword
									self.alert( warning+"\n"+error+endLine)
								elif secretword=="password":
									error="\t\tChange password! It is very dangerous to use default one!"
									troubleId+=1
									warning="TOMCAT_WARNING ("+str(troubleId)+") Default password for for "+part+": user="+nm+", pass="+secretword
									self.alert( warning+"\n"+error+endLine)
								elif secretword=="manager":
									error="\t\tChange password! It is very dangerous to use default one!"
									troubleId+=1
									warning="TOMCAT_WARNING ("+str(troubleId)+") Default password for for "+part+": user="+nm+", pass="+secretword
									self.alert( warning+"\n"+error+endLine)
								elif secretword=="role1":
									error="\t\tChange password! It is very dangerous to use default one!"
									troubleId+=1
									warning="TOMCAT_WARNING ("+str(troubleId)+") Default password for for "+part+": user="+nm+", pass="+secretword
									self.alert( warning+"\n"+error+endLine)
								elif secretword=="password":
									error="\t\tChange password! It is very dangerous to use default one!"
									troubleId+=1
									warning="TOMCAT_WARNING ("+str(troubleId)+") Default password for for "+part+": user="+nm+", pass="+secretword
									self.alert( warning+"\n"+error+endLine)
								elif secretword=="admin":
									error="\t\tChange password! It is very dangerous to use default one!"
									troubleId+=1
									warning="TOMCAT_WARNING ("+str(troubleId)+") Default password for for "+part+": user="+nm+", pass="+secretword
									self.alert( warning+"\n"+error+endLine)
								elif bool(not re.match(r".*[0-9].*",secretword) or not re.match(r".*[a-z].*",secretword) or not re.match(r".*[\~\!\@\#\$\%\^\&\*\(\)\?\!\?\;\:\?\\\/\{\[\]\}].*",secretword) or not re.match(r".*[A-Z].*",secretword) or len(secretword)<7):
									error="\t\tHINT: Len>6, uppercase, loweracse, digit, symbol\n\t\tBe sure that this port firewaled!"
									troubleId+=1
									warning="TOMCAT_WARNING ("+str(troubleId)+") Weak password for for "+part+": user="+nm+", pass="+secretword
									self.alert( warning+"\n"+error+endLine)
									
			dprint (2, "\n\tParsing /manager/WEB-INF/web.xml...")
			
			
			serverXML=catalinaHome+"/webapps/manager/WEB-INF/web.xml"
			if os.path.exists(serverXML):
				error="\n\t\tWhen you access the password-protected manager webapp,\n\t\tthe password you enter will be sent over the network in (nearly)\n\t\tplain text, ripe for interception. By using an SSL connection instead, \n\t\tyou can transport the password securely. Fortunately, this is simple to accomplish.\n\t\tAfter configuring an SSL Connector in server.xml (see your Tomcat documentation), \n\t\tsimply add the following to CATALINA_HOME/webapps/manager/WEB-INF/web.xml inside of the\n\t\t<security-constraint></security-constraint> tags, like:\n\t\t\n\t\t\t<user-data-constraint>\n\t\t\t\t<transport-guarantee>CONFIDENTIAL</transport-guarantee>\n\t\t\t</user-data-constraint>\n"
				xml = parse(serverXML)
				if len(xml.getElementsByTagName("security-constraint")):
					if len(xml.getElementsByTagName("security-constraint")[0].getElementsByTagName("user-data-constraint")):
						if len(xml.getElementsByTagName("security-constraint")[0].getElementsByTagName("user-data-constraint")[0].getElementsByTagName("transport-guarantee")):
							sslSet=self.getText((xml.getElementsByTagName("security-constraint")[0].getElementsByTagName("user-data-constraint")[0].getElementsByTagName("transport-guarantee")[0]).childNodes)
							if not re.match("^[\n\s]*CONFIDENTIAL[\n\s]*$",sslSet):
								#error="\t\t"
								troubleId+=1
								warning="TOMCAT_WARNING ("+str(troubleId)+") transport-guarantee is not CONFIDENTIAL!"
								self.alert( warning+"\n"+error+endLine)
						else:
							#error="\t\t"
							troubleId+=1
							warning="TOMCAT_WARNING ("+str(troubleId)+") transport-guarantee is not defined!"
							self.alert( warning+"\n"+error+endLine)
						
					else:
						#error="\t\t"
						troubleId+=1
						warning="TOMCAT_WARNING ("+str(troubleId)+") transport-guarantee is not defined!"
						self.alert( warning+"\n"+error+endLine)
				else:
					#error="\t\t"
					troubleId+=1
					warning="TOMCAT_WARNING ("+str(troubleId)+") security-constraint is not defined!"
					self.alert( warning+"\n"+error+endLine)

		### SecurityManager

				
		dprint (2, "\n#Security Manager...\n")

		cfg="[fake_section]\n"

		#defCfg="/etc/default/tomcat"+str(tomcatVer)
		mainCfg=catalinaHome+"/conf/tomcat"+str(self.tomcatVer)+".conf"
		config = ConfigParser.RawConfigParser()

		res=""

		if os.path.exists(mainCfg):
			cfg += open(mainCfg, 'r').read()
			config.readfp(io.BytesIO(cfg))
			res = ((str(config.get("fake_section", "SECURITY_MANAGER")).strip("\"")).strip("'")).lower()
			
			dprint (2, "\tINFO: Security Manager set in '"+res+"'")

			if res not in ["yes","on","true","1"]:
				troubleId+=1
				warning="TOMCAT_WARNING ("+str(troubleId)+") Security Manager is not enabled!"
				self.alert(warning+"\n"+"\t\tEnable Security Manager for Tomcat in "+mainCfg+":\n\t\t\tSECURITY_MANAGER=\"true\"\n"+endLine)

		#the end





	##-------------


# Apache checker
#
# Check config files for:
# 	1)modules
# 	2)banner
# 	3)owner
#	4)log level
#	5)directories options (indexes/)
#
#  
#



############### n00b Parser 8)))
#
# TODO: add multi-line support like "\"
#
class Node(object):
	def __init__(self):
		self.name=None
		self.args=[]
		self.stable = True
	def addLine2(self,line):
		self.stable = True
		if line[-1] == "\\": # TODO: add multi-line support like "\"
			line = line[:-1]
			self.stable = False
			dprint(2, "ERROR: NOT SUPPORTETD FORMAT: "+line)
			exit(0)
		parts = line.strip().split()
		self.name = parts[0]
		self.args = parts[1:]
		#print "INIT N: "+self.name+" ->> "+", ".join(self.args)

class Complex(Node):
	MATCH_RE_EMPTY = r"\s*#(.*[^\\])?$"
	MATCH_RE_COMMENT = "\s*$"
	NAME_RE_WORD = "[a-zA-Z]\w*"
	MATCH_RE_DIRECTIVE = r"\s*%s(\s+.*)*\s*[\\]?$" % NAME_RE_WORD
	MATCH_RE_COMPLEX = r"\s*<\s*%s(\s+[^>]*)*\s*(>\s*|[\\])$" % NAME_RE_WORD
	MATCH_RE_COMPLEXEND="\s*</%s>\s*$"

	def __init__(self):
		super(Complex, self).__init__()
		self.body=None
		self.header=None
		self.complete=True
		self.deep=0

	def matchEmpty(self,line):
		if line is None:
			return False
		return bool( re.match(self.MATCH_RE_EMPTY, line) or re.match(self.MATCH_RE_COMMENT, line))

	def matchDirective(self,line):
		if line is None:
			return False
		return bool( re.match(self.MATCH_RE_DIRECTIVE, line))

	def matchComplex(self,line):
		if line is None:
			return False
		return bool( re.match(self.MATCH_RE_COMPLEX, line))
	def matchComplexEnd(self,line,name):
		if line is None:
			return False
		return bool( re.match(self.MATCH_RE_COMPLEXEND % name, line))
################
	def addLine(self,line):
		if self.matchEmpty(line):
			return
		#Directive?
		if self.matchDirective(line):
			#print "DIR: "+line
			self.addLine2(line)
			if not self.stable:
				self.complete=False
		#Complex?
		elif self.matchComplex(line):
			#print "COM: "+line
			if self.complete:
				self.complete=False
				header=line.lstrip()
				header=header.rstrip()
				header=header.strip("<>")
				self.addLine2(header)
				self.header=header
		else:
			return
	def newChild(self):
		if not self.header:
			dprint(0," PARSING ERROR 1H "+line)
			exit(0)
		elif self.complete==True:
			dprint(0," PARSING ERROR 1T "+line)
			exit(0)
		else:
			self.body=HTTPDNodes()
	def addChild(self,line):
		if not self.header:
			dprint(0," PARSING ERROR 2H "+line)
			exit(0)
		elif self.complete==True:
			dprint(0," PARSING ERROR 2T "+line)
			exit(0)
		elif not self.body:
			dprint(0," PARSING ERROR 2B "+line)
			exit(0)
		else:
			self.body.addLine(line)
			if self.name!=None and self.matchComplexEnd(line,self.name):
				#print "_COM: "+line
				self.complete=True
#####################

class HTTPDNodes(object):

	def __init__(self):
		self.complete2=True
		self._nodes=[]

	def addLine(self,line):
		#Empty or Comment?
		##print "addLine()"
		if not self.complete2:
			##print "not compl2"
			if self._nodes[-1].complete:
				##print "but compl"
				self.complete2=True
			else:
				##print "not compl"
				self._nodes[-1].addChild(line)
		##print "cnt"
		if self.complete2:
			##print "not compl2"
			newNode=Complex()
			newNode.addLine(line)

			if newNode.complete:
				self._nodes.append(newNode)
			elif newNode.header:
				newNode.newChild()
				self._nodes.append(newNode)
				self.complete2=False
			else:
				dprint(1,"PARSING ERROR")
				exit(0)
	def getDirectives(self,name,idx):
		retD=[]
		for node in self._nodes:
			if(str(node.name).lower()==str(name).lower() and len(node.args)>idx):
				if (idx<0):
					for ar in node.args:
						retD.append(str(ar))
				else:
					retD.append(str(node.args[idx]))
		return retD
	def getDirectories(self,name):
		retD={}
		for node in self._nodes:
			if(str(node.name).lower()==str(name).lower() and node.body):
				if len(node.args)>0:
					retD[node.args[0]]=node.body
				else:
					retD['']=node.body
		return retD

class ApacheConfParser2(HTTPDNodes):
	def __init__(self, source_f, infile=True, delay=False, count=None,source=[]):
		super(ApacheConfParser2, self).__init__()
		self.source=[]
		for file in source_f:
			file=str(file)
			#file=file.splitlines()
			for line in open(file):
				self.source.append(line.strip("\n"))
		self.count = count
		self.parse()
	def parse(self):
		lineTmp=""
		for line in self.source:
			if self.count is not None:
				dprint(1,self.count)
				self.count += 1
			if len(line)>0:	
				if line[-1] == "\\":
					lineTmp+=line[:-1];
				else:
					lineTmp+=line
					self.addLine(lineTmp)
					lineTmp=""
############ END PARSER ######################

###############
# Main class for Apache check
###############

class ApacheConfigCheck(GenericCheck):
	check_id = 0x0A000001;
	alerts = [];
	mainConf=""
	confFiles=[]
	badModules=[]
	goodModules=[]
	def __init__(self,_list=Modules_wl):
		self.badModules=_list[0]
		self.goodModules=_list[1]
	def check_prereq(self):
		dprint (1, self.__class__.__name__+" prereq "+str(os.geteuid()));

		baseHTTPD=""
		self.run=1
		if (ts.dbMatch( 'name', 'apache')):
			mi = ts.dbMatch( 'name', 'apache')
		elif (ts.dbMatch( 'name', 'apache2')):
			mi = ts.dbMatch( 'name', 'apache2')
		elif (ts.dbMatch( 'name', 'httpd')):
			mi = ts.dbMatch( 'name', 'httpd')
		else:
			dprint(1,"ERROR! Can't find Apache...")
			self.run=0
			return

		baseHTTPD=mi.next().fiFromHeader()[0] # need some tests to verify that fires element alway /etc/httpd or other base, but looks like true
		self.mainConf=baseHTTPD+"/conf/httpd.conf"
		dirConf=baseHTTPD+"/conf.d/"
		if os.path.exists(self.mainConf):
			dprint(2,"# "+self.mainConf+" found!\n")
			self.confFiles.append(self.mainConf)
			self.run=1
		else:
			dprint(1,"ERROR! Check path to config file...")
			self.run=0
			return
		if os.path.exists(dirConf): # TODO, just enum  - not cheks!
			fileList = os.listdir(dirConf)
			fileList=filter(lambda x: x.endswith('.conf'), fileList);
			for file in fileList:
				dprint(2,"# "+self.mainConf+" found!\n")
				self.confFiles.append(dirConf+file)
		
	def run_check(self):
		dprint (1, self.__class__.__name__+" run_check ");
		#Stage 0.
		endLine="\n--------------------------------------------------------------------------------"
		dprint (2,"\n### Starting apache hardening ... \n\nConfig files:")

		#Stage 0.5 Parsing main conf
		mainObj=ApacheConfParser2(self.confFiles)
		#########################################

		troubleId=0;
		dprint (2, "\n")
		##########################################
		#Stage 1. Unwanted modules
		##########################################
		#Descrip
		descModules={}

		descModules['security2_module']="\tINFO: Web Application Firewall not used. \n\tIf it possible use mod_security for Apache. Info:http://www.modsecurity.org/"
		descModules['info_module']="\tINFORMATION_DISCLOSURE: This module can be used for inf. disclosure. \n\tPlease remove it, if it is possible."
		descModules['status_module']="\tINFORMATION_DISCLOSURE: This module can be used for inf. disclosure. \n\tPlease remove it, if it is possible."
		descModules['userdir_module']="\tINFORMATION_DISCLOSURE: This module can be used for inf. disclosure. \n\tPlease remove it, if it is possible."

		dprint(2, "\n##### Modules ######")
		##########################################
		#Modules in modules
		modules=mainObj.getDirectives('LoadModule',0)
		
		goodModules=self.goodModules
		badModules=self.badModules
		
		#Check for good
		for good in goodModules:
			if good not in modules:
				troubleId+=1;
				repo="HTTPD_WARNING ("+str(troubleId)+") # Module "+good+" is not loaded! Please INSTALL it. "
				if good in descModules:
					repo+="\n\t"+descModules[good]
				self.alert(repo+endLine)


		#Check for bad

		for bad in badModules:
			if bad in modules:
				troubleId+=1;
				repo="HTTPD_WARNING ("+str(troubleId)+") # Module "+bad+" is loaded! Please REMOVE it if it is possible. "
				if bad in descModules:
					repo+="\n\t"+descModules[bad]
				self.alert(repo+endLine)

		######### End satge 1 ###################

		##########################################
		#Stage 2. Banner grab
		##########################################
		descSign1=['','','']
		descSign2=['','','']

		descSign1[0]='INFORMATION_DISCLOSURE:\'ServerTokens\' value is not \'ProductOnly\'. \n\tIn this case banner returns some informaion about Apache version and OS. \n\tPlease change this setting to \'ServerTokens ProductOnly\' in httpd.conf'
		descSign1[1]=''
		descSign1[2]='INFORMATION_DISCLOSURE: You have default value (Full)  of \'ServerTokens\'. \n\tBanner returns full information about Apache version, modules and OS. \n\tPlease set \'ServerTokens ProductOnly\' in httpd.conf'


		descSign2[0]='INFORMATION_DISCLOSURE: \'ServerSignature\' value is not \'Off\'. \n\tIn this case  Apache returns version and OS information. \n\tPlease change this setting to \'ServerSignature Off\' in httpd.conf or remove it'
		descSign2[1]=''

		dprint(2,"\n###### Banners ######")
		##########################################
		badSign1=0
		badSign2=0
		signNow=['','']

		serverToken=mainObj.getDirectives('ServerTokens',0)
		serverSign=mainObj.getDirectives('ServerSignature',0)

		if len(serverToken)>0:
			signNow[0]=serverToken[0]
			if re.match("ProductOnly",signNow[0], re.IGNORECASE) or re.match("Prod",signNow[0], re.IGNORECASE):
				badSign1=1
		else:
			signNow[0]='Default: Full'
			badSign1=2

		if len(serverSign)>0:
			signNow[1]=serverSign[0]
			if re.match("Off",signNow[1],re.IGNORECASE):
				badSign2=1
		else:
			signNow[1]='Default: Off'
			badSign2=1

		if(badSign1!=1):
			troubleId+=1;
			repo="HTTPD_WARNING ("+str(troubleId)+") # Apache banner returns version details!. Change ServerTokens option in httpd.conf."
			repo+="\n\t"+descSign1[badSign1]
			self.alert(repo+endLine)

		if(badSign2!=1):
			troubleId+=1;
			repo="HTTPD_WARNING ("+str(troubleId)+") # Apache pages returns version details!. Change ServerSignature option in httpd.conf."
			repo+="\n\t"+descSign2[badSign2]
			self.alert(repo+endLine)

		######### End satge 2 ###################

		##########################################
		#Stage 3. LogLevel
		##########################################
		descLog='The recommended level is notice, \n\tso that all errors from the emerg level through notice level will be logged.'

		dprint(2,"\n###### LogLevel ######")
		##########################################
		logLvl=mainObj.getDirectives('LogLevel',0)

		if len(logLvl)>0:
			if re.match("(emerg)|(alert)|(crit)|(error)",str(logLvl[0]), re.IGNORECASE):
				troubleId+=1;
				repo="HTTPD_WARNING ("+str(troubleId)+") # LogLevel value is \'"+str(logLvl[0])+"\'"
				repo+="\n\t"+"HIGH: LogLevel is less than warn! "+descLog
				self.alert(repo+endLine)
			elif not re.match("notice",str(logLvl[0]), re.IGNORECASE):
				troubleId+=1;
				repo="HTTPD_WARNING ("+str(troubleId)+") # LogLevel value is \'"+str(logLvl[0])+"\'"
				repo+="\n\t"+"LOW: "+descLog
				self.alert(repo+endLine)
		else:
			troubleId+=1;
			repo="HTTPD_WARNING ("+str(troubleId)+") # LogLevel value is not \'notice\'!"
			repo+="\n\t"+"HIGH: LogLevel is not set. "+descLog
			self.alert(repo+endLine)

		######### End satge 3 ###################

		##########################################
		#Stage 3/5. User/Group
		##########################################
		dprint (2,"\n###### User/Group ######")
		##########################################
		usr=mainObj.getDirectives('User',0)
		grp=mainObj.getDirectives('Group',0)

		if len(usr)>0:
			if re.match("nobody",str(usr[0]), re.IGNORECASE):
				troubleId+=1;
				repo="HTTPD_WARNING ("+str(troubleId)+") # Apache's user is nobody"
				repo+="\n\t"+"HIGH: Add user for an Apache: 'www' or 'apache'"
				self.alert(repo+endLine)
		if len(grp)>0:
			if re.match("nobody",str(grp[0]), re.IGNORECASE):
				troubleId+=1;
				repo="HTTPD_WARNING ("+str(troubleId)+") # Apache's group is nobody"
				repo+="\n\t"+"HIGH: Add group for an Apache: 'www' or 'apache'"
				self.alert(repo+endLine)

		######### End satge 3/5 ###################

		############BIG ONE#######################
		##########################################
		#Stage 4. Dirs
		##########################################

		dprint(2,"\n###### Directories ######")
		##########################################

		objDirs=mainObj.getDirectories('Directory')

		fullOptions={}

		if len(objDirs)>0:
			for nm,vl in objDirs.iteritems():
				if nm =='/' or nm=='"/"': # Root dir checks
					deny=0
					if len(vl.getDirectives('Deny',0)):
						if re.match("from",vl.getDirectives('Deny',0)[0],re.IGNORECASE) and re.match("all",vl.getDirectives('Deny',1)[0],re.IGNORECASE):
							deny=1
					if(deny==0):
						troubleId+=1
						repo="HTTPD_WARNING ("+str(troubleId)+") # Settings for "+nm+" are not secure!"
						repo+="\n\t"+"HIGH: set in <Directory \"/\"> --> \'Deny from all\' to prevent access to root"
						self.alert(repo+endLine)
					deny=0
					if len(vl.getDirectives('AllowOverride',0)):
						if re.match("None",vl.getDirectives('AllowOverride',0)[0],re.IGNORECASE):
							deny=1
					if(deny==0):
						troubleId+=1
						repo="HTTPD_WARNING ("+str(troubleId)+") # Settings for "+nm+" are not secure!"
						repo+="\n\t"+"HIGH: set in <Directory \"/\"> --> \'AllowOverride None\'!"
						self.alert(repo+endLine)

				#Options check
				if vl.getDirectives('Options',0):
					options=vl.getDirectives('Options',-1)
					optList=[]
					optList.extend(options)
					fullOptions[nm]=optList


			rootDir=[]
			#Indexes


			if '/' in fullOptions:
				rootDir=fullOptions['/']
			if '"/"' in fullOptions:
				rootDir=fullOptions['"/"']

			minus=0
			if len(rootDir)>0: #Over
				#print "\nINFO: Options by default for ALL Directories:\'Options "+" ".join(rootDir)+"\' \n\tMust be: \'Options None\' (<Directory\"/\">)\n"
				if 'None' in rootDir:
					minus=1
				else:
					troubleId=troubleId+1
					repo="HTTPD_WARNING ("+str(troubleId)+") # Settings for / direcory are not secure!"
					repo+="\n\t"+"HIGH: Those options are not set: None. \n\tPlease set it like: \'Options None\'. \n\tCurrent settings:\'Options "+" ".join(rootDir)+"\'"
					self.alert(repo+endLine)
			else:
				troubleId=troubleId+1
				repo="HTTPD_WARNING ("+str(troubleId)+") # Settings for / direcory are not set! (All - by deafult)"
				repo+="\n\t"+"HIGH: Those options are not set: None. \n\tPlease set it like: \'Options None\'. \n\tCurrent settings:\'Options All\'"
				self.alert(repo+endLine)

			for nm,optList in fullOptions.iteritems():
				if nm!="/" and nm!='"/"':
					notOpt=""
					badOpt=""
					areOpt=" "+" ".join(optList)
					notList=[False,False,False,False]
					if not minus:
						if  '-Indexes' not in optList and('Indexes' in rootDir or 'All' in rootDir):
							notOpt+='-Indexes '
							notList[0]=True
						if  '-FollowSymLinks' not in optList and('FollowSymLinks' in rootDir or 'All' in rootDir):
							notOpt+='-FollowSymLinks '
							notList[0]=True
						if  '-Includes' not in optList and('Includes' in rootDir or 'All' in rootDir):
							notOpt+='-Includes '
							notList[0]=True
						if  '-MultiViews' not in optList and('MultiViews' in rootDir or 'All' in rootDir):
							notOpt+='-MultiViews '
							notList[0]=True
						if  'None'  in optList: #Over
							notOpt=""
							notList=[True,True,True,True]
					if  'Indexes' in optList or (('Indexes' in rootDir or 'All' in rootDir) and (notList[0])):
						badOpt+='Indexes '
					if  'FollowSymLinks' in optList  or (('FollowSymLinks' in rootDir or 'All' in rootDir) and (notList[1])):
						badOpt+='FollowSymLinks '
					if  'Includes' in optList  or (('Includes' in rootDir or 'All' in rootDir) and (notList[2])):
						badOpt+='Includes '
					if  'MultiViews' in optList  or (('MultiViews' in rootDir or 'All' in rootDir) and (notList[3])):
						badOpt+='MultiViews '
					if  'All' in optList:
						badOpt+='All '
					if  'None'  in optList: #Over
						badOpt=''

					if len(optList)==0:
						troubleId=troubleId+1
						repo="HTTPD_WARNING ("+str(troubleId)+") # Settings for "+nm+" direcory are not secure! (All - by deafult)"
						repo+="\n\t"+"HIGH: Those options are not set: None. \n\tPlease set it like: \'Options -FollowSymLinks -Includes -Indexes -MultiViews\'. \n\tCurrent settings:\'Options All\'"
						self.alert(repo+endLine)

					if notOpt!="":
						troubleId=troubleId+1
						repo="HTTPD_WARNING ("+str(troubleId)+") # Settings for "+nm+" are not secure!"
						repo+="\n\t"+"HIGH: Those options are not set: "+notOpt+". \n\tPlease set it like: \'Options -FollowSymLinks -Includes -Indexes -MultiViews\'. \n\tCurrent settings:\'Options "+areOpt+"\'"
						self.alert(repo+endLine)

					if badOpt!="":
						troubleId=troubleId+1
						repo="HTTPD_WARNING ("+str(troubleId)+") # Settings for "+nm+" are not secure!"
						repo+="\n\t"+"HIGH: Those options are set: "+badOpt+". \n\tPlease remove it or set it like: \'Options -FollowSymLinks -Includes -Indexes -MultiViews\'. \n\tCurrent settings:\'Options "+areOpt+"\'"
						self.alert(repo+endLine)

		######### End satge 4 ###################

##################################################################

# User with password 
class UserWithPasswordCheck(GenericCheck):
  check_id = 0x00000001;
  alerts = [];
  def check_prereq(self):
    dprint (1, self.__class__.__name__+" prereq "+str(os.geteuid()));
    if(os.geteuid() != 0):
      self.run=0;
    else:
      self.run=1
  def run_check(self):
    dprint (1, self.__class__.__name__+" run_check ");
    for entry in spwd.getspall():
      # if hash size in entry is more than 3 (x,!!,!,etc.)
      if len(entry[1]) > 3 :
        self.alert(entry[0])
##################################################################

# iptables v4 Default policy DROP 
class FirewallDefaultPolicyCheck(GenericCheck):
  check_id = 0b00000010;
  alerts = [];
  def check_prereq(self):
    dprint (1, self.__class__.__name__+" prereq "+str(os.geteuid()));
    if(os.geteuid() != 0):
      self.run=0;
    else:
      self.run=1;
  def run_check(self):
    dprint (1, self.__class__.__name__+" run_check ");
    procin,procout = os.popen4('which iptables');
    iptables_cmd = procout.readline().rstrip();
    procout.readlines();
    procout.close();
    procin.close();
    if iptables_cmd.find('no iptables') >= 0:
      self.alert('NOT_FOUND');
    else:
      proc = os.popen(iptables_cmd+' -S');
      for rule in proc:
        rule = rule.strip();
        rule_def = rule.split()
        if rule_def[0] == '-P' and rule_def[2] == 'ACCEPT':
          self.alert(rule_def[1])
      proc.close();

##################################################################

# SSHD config options check 
class SSHDConfigCheck(GenericCheck):
  check_id = 0x00000002;
  alerts = [];
  sshd_cmd = '';
  def check_prereq(self):
    dprint (1, self.__class__.__name__+" prereq "+str(os.geteuid()));
    procin,procout = os.popen4('which sshd');
    sshd_cmd = procout.readline().rstrip();
    procout.readlines();
    procout.close();
    procin.close();
    if (sshd_cmd.find('no sshd') >= 0 or os.geteuid() != 0):
      self.run=0;
    else:
      self.sshd_cmd = sshd_cmd;
      self.run=1;
  def run_check(self):
    dprint (1, self.__class__.__name__+" run_check ");
    proc = os.popen('strings '+self.sshd_cmd+'|grep sshd_config');
    sshd_config = proc.readline().rstrip();
    proc.readlines();
    proc.close();
    client_alive = 0;
    config = open(sshd_config);
    for line in config:
      line = line.rstrip();
      if line[:1] == '#' or not line.strip():
        continue;
      conf = line.split()
      if conf[0] == 'Protocol':
        if conf[1].find('1') >= 0:
          self.alert('Protocol 1 supported');
      elif conf[0] == 'PermitEmptyPasswords':
        if conf[1].lower().find('yes') >= 0:
          self.alert('Empty passwords allowed');
      elif conf[0] == 'PermitRootLogin':
        if conf[1].lower().find('yes') >= 0:
          self.alert('Root is allowed to login');
      elif conf[0] == 'IgnoreRhosts':
        if conf[1].lower().find('no') >= 0:
          self.alert('User .rhosts files are not ignored');
      elif conf[0] == 'HostbasedAuthentication':
        if conf[1].lower().find('yes') >= 0:
          self.alert('HostbasedAuthentication is enabled');
      elif conf[0] == 'RhostsRSAAuthentication':
        if conf[1].lower().find('yes') >= 0:
          self.alert('RhostsRSAAuthentication is enabled');
      elif conf[0] == 'ClientAliveInterval':
        client_alive = string.atoi(conf[1]);
      elif conf[0] == 'PermitUserEnvironment':
        if conf[1].lower().find('yes') >= 0:
          self.alert('PermitUserEnvironment is enabled');

    if client_alive == 0:
      self.alert('ClientAliveInterval not set')

    config.close();

##################################################################
# TCPIP Hardening config checks 
class TCPIPHardeningConfigCheck(GenericCheck):
  check_id = 0x0B000001;
  alerts = [];
  syscltFileName = "/etc/sysctl.conf"

  def check_prereq(self):
    dprint (1, self.__class__.__name__+" prereq "+str(os.geteuid()));
    self.run=1;
    try:
      self.run=1;
      self.syscltFile = open(self.syscltFileName, 'r')
    except Exception as  e:
      print ("\tError opening " + self.syscltFileName + str(e))
      self.run=0;

  def TcpIPChecks(self,sysctl_checklist):
    dprint(2,"### TCP/IP Checks ###")
    syscltFileContent = ''.join(self.syscltFile.readlines())
    errorCounter = 0;
    for check, (errorMsg, value) in sysctl_checklist.items():

	   # check for matches of sysctl_checlisk item in /etc/sysctl
        match = re.search(check, syscltFileContent , re.IGNORECASE)

        value = sysctl_checklist[check]['value']
        errorMsg = sysctl_checklist[check]['message']

	   # removing all the regex paramters from the configuration item name
        check = check.split ('\s*')[1]

        # check for the same paramter in memory
        memoryCheckFilename = "/proc/sys/" + check.replace('.','/')
        try:
            memoryCheckFile = open(memoryCheckFilename,'r')
        except Exception as  e:
            print ("\tError opening file " + memoryCheckFilename)
            print
            continue

        # removing the '\n' at the end of the read file
    	memoryCheckFileContent = memoryCheckFile.read().strip()

        if (not match):
            errorCounter+=1
            errorString = "TCP_WARNING (" + str(errorCounter) + ") # "+ errorMsg + " Fix by setting:\n\t"+ check + ' = ' + value

            if memoryCheckFileContent != value:
                errorString = errorString + "\n\t# In Memory also: " +  errorMsg + " Fix by issuing:\n\
                  /usr/sbin/sysctl -w " + check + "=" + value

            errorString = errorString + '\n'+'-'*80
            self.alert(errorString)

        if (match and memoryCheckFileContent != value):
            errorCounter+=1
            errorString = "TCP_WARNING ("+ str(errorCounter) + ") *** Configuration mismatch between "+ self.syscltFileName + " and configuration in MEMORY\n\
            \tThat means the system needs reboot to apply /etc/sysctl.conf configuration\n\
            \t  Or "+ errorMsg + " Fix by issuing:\n \
            /usr/sbin/sysctl -w " + check + "=" + value

            errorString = errorString + '\n'+'-'*80
            self.alert(errorString)
            memoryCheckFile.close()
    self.syscltFile.close()

  def run_check(self):
    dprint (1, self.__class__.__name__+" run_check ")
    self.TcpIPChecks(sysctl_ipv4_checklist)

    # TcpIPChecks(sysctl_ipv6_checklist)
##################################################################

# File permissions checks (by Nader)
class FilePermissionsCheck(GenericCheck):
	check_id = 0x0B000002;
	alerts = [];

	dirFilter = ['/dev', '/proc', '/sys']
	worldWritableDirs = []
	worldWritableFiles = []
	unownedFiles=[]
	worldReadableLogs = []
	SUIDFiles = []
	warningCount =0

	def check_prereq(self):
		dprint (1, self.__class__.__name__+" prereq "+str(os.geteuid()));
		self.run=1;
		try:
			self.run=1;
		except Exception as e:
			self.run=0;
	
	def walktree(self,baseDir):
		for file in os.listdir(baseDir):
			pathName = os.path.join(baseDir, file)
			if pathName in self.dirFilter: continue
			try:
				fileStat = os.stat(pathName)
				mode = fileStat.st_mode
				modePerm = stat.S_IMODE(mode)
			except Exception as e:
				dprint(2, "Error " + str(e))
				continue
			if stat.S_ISREG(mode):
				# Check for unowned files
				try:
					pwd.getpwuid(fileStat[stat.ST_UID])
				except (ImportError, KeyError):
					dprint(2, "UID Exception ")
					self.unownedFiles.append(pathName)
	
				# Check for World-Writable files
				if modePerm & stat.S_IWOTH:
					self.worldWritableFiles.append(pathName)

				# Check for World-Readable Log files
				if (modePerm & stat.S_IROTH) and (pathName.find("/var/log/")!= -1):
					self.worldReadableLogs.append(pathName)
		
				# Check for SUID, GUID Files
				if (modePerm & stat.S_ISUID or modePerm & stat.S_ISGID) and (modePerm & stat.S_IWOTH):
					self.SUIDFiles.append(pathName)

			elif stat.S_ISDIR(mode):
				# Check for World-Writable directories without Sticky bit
				if( modePerm & stat.S_IWOTH) and (modePerm & stat.S_ISVTX == 0):
					self.worldWritableDirs.append(pathName)
				if (modePerm & stat.S_IROTH)  :
					self.walktree(pathName)

	dprint (2, "*** File permissions check finished! ***")

	def run_check(self):
		dprint (1, self.__class__.__name__+" run_check ")
		self.walktree('/')
    
		if self.worldWritableDirs:
			self.warningCount+=1
			errorString = "FileCheck WARNING(" + str(self.warningCount) + ") :  #World-Writable directories without have sticky bits set :\n#Fix :use chmod +t /dir for these directories\n"
			for i in self.worldWritableDirs:
				errorString = errorString + '\t' + str(i) +'\n'
			errorString = errorString + '-'*80
			self.alert(errorString)

		if self.worldWritableFiles:
			self.warningCount+=1	
			errorString = "FileCheck WARNING(" + str(self.warningCount) + ") : #World-Writable files :\n#Fix : use chmod o-w for these files\n"
			for i in self.worldWritableFiles:
				errorString = errorString + '\t'+ str(i) +'\n'
			errorString = errorString + '-'*80
			self.alert(errorString)

		if self.unownedFiles:
			self.warningCount+=1	
			errorString = "FileCheck WARNING(" + str(self.warningCount) + ") :  #Unowned Files :\n#Fix : investigate each reported file and either assign it to an appropriate user and group or remove it\n"
			for i in self.unownedFiles:
				errorString = errorString + '\t'+ str(i) +'\n'
			errorString = errorString + '-'*80
			self.alert(errorString)

		if self.worldReadableLogs:
			self.warningCount+=1	
			errorString = "FileCheck WARNING(" + str(self.warningCount) + ") :  #World readable log files :\n#Fix :  use chmod o-r for these files\n"
			for i in self.worldReadableLogs:
				errorString = errorString + '\t'+ str(i) +'\n'
			errorString = errorString + '-'*80
			self.alert(errorString)

		if self.SUIDFiles:
			self.warningCount+=1	
			errorString = "FileCheck WARNING(" + str(self.warningCount) + ") :  #World writable files with SUID set!! :\n#Fix :  Please review these files and revoke world reable / suid permissions\n"
			for i in self.SUIDFiles:
				errorString = errorString + '\t'+ str(i) +'\n'
			errorString = errorString + '-'*80
			self.alert(errorString)


###################################################################

# PHP configuration checks (by Nader)
class PHPConfigCheck(GenericCheck):
	check_id = 0x0B000003;
	alerts = [];
	iniFilename = "";
	warningCount= 0;

	# Checks for the "[PHP]" section in PHP.ini
	phpSectionCheckList = {
        "register_globals" :  {"value" : "Off", "message" :" Please turn off register_globals"},\
        "allow_url_fopen": {"value" :"Off", "message" :"Please turn off remote file includes"}, \
	"file_uploads":{"value":"Off","message":"Please turn off local file includes"},\
        "disable_functions" :  {"value" : "exec(),eval(),phpinfo(),passthru(),shell_exec(),system()", "message":"Please disable these exec(),eval(),phpinfo(),shell_exec(),system()"}, \
        "enable_dl" : { "value" :"Off", "message" : "Please turn off enable_dl"}, \
        "display_errors" : { "value" :"Off", "message" : "Please disable display_errors for production"}, \
        "log_errors" : { "value" :"On", "message" : "Please turn on logging error for production"},  \
        "error_reporting" : { "value" :"E_ALL", "message" : "Please turn on all error reporting"},\
        "safe_mode" : { "value" :"On", "message" : "Please enable safe mode, if safe mode is enabled, you can overlook enable_dl configuration."},\
        "open_basedir" : { "value" :"where the application loads data", "message" : "Please configure the folders that your application need to access"}
        }

	def check_prereq(self):
		dprint (1, self.__class__.__name__+" prereq "+str(os.geteuid()));
		self.run=1;
		try:
			#getting the location of php.ini file
			phpFileLocation, _stdin, _error = popen2.popen3(" php -r \"phpinfo();\" | grep 'Loaded Configuration File'" )

			if phpFileLocation :
				s = phpFileLocation.read()
				start = s.find('=> ', (s.find('File')+ 4)) +3
				end = s.find('\n',start)
				self.iniFilename = s[start:end]
				dprint(2, "Found php.ini file : " + self.iniFilename)
			else:
				raise exception

			try:			
				iniFileHandle = open(self.iniFilename, 'r')
				dprint(2,"# Opening " + self.iniFilename + "... ")
				iniFileHandle.close()
			except:
				dprint (2, "\tError opening" + self.iniFilename + str(e))
				raise exception
			self.run=1;
		except Exception as  e:
			dprint(2, "Error : " + str(e))
			dprint (2,"Can not locate php.ini ....")
        		dprint(2, "PHP Configuration Assessment is NOT complete!")
			self.run=0;
	
	def run_check(self):
		dprint (1, self.__class__.__name__+" run_check ")
		# Creating a parser
		phpIni = ConfigParser.RawConfigParser();
		phpIni.read(self.iniFilename);

		# checking against PHP section
		# just boolean if the item is not found at all in the php.ini file
		notFound = 0
		for k,(m,v) in self.phpSectionCheckList.items():
			try:
				check = phpIni.get("PHP",k)
			except Exception as e:
	    			notFound = 1
			if (self.phpSectionCheckList[k][v] != check) or (notFound == 1):
				self.warningCount+=1	
				errorString = "PHP WARNING(" + str(self.warningCount) + ") :"
				errorString += "\n" + self.phpSectionCheckList[k][m]
				errorString += "\n\t  Recommended configuration : "+ k + " = " + self.phpSectionCheckList[k][v]
				if notFound:
					errorString += "\n\t  Currently " + k + " is not configured \n"
					notFound = 0
				else:
					errorString += "\n\t  Current value is : " + k + " = " + check + '\n'
					# returns to default notFound value for next items


				errorString = errorString + '-'*80
				self.alert(errorString)

##################################################################
#                           END                                  #
##################################################################


##### Engine, options
def checkOpts():
    usage = "usage: %prog [options] for more help: %prog -h"
    version = "v1.0"
    parser = OptionParser(usage)
    parser.add_option("--debug","-d", \
                        action="store", \
                        dest="DEBUG",\
                        type="int", \
                        help="Debug level")

    parser.add_option("--list","-l", \
                        action="store_true", \
                        dest="LISTCHECKS",\
                        help="List Checks")

    parser.add_option("--report","-r", \
                        action="store", \
                        dest="REPORT",\
                        type="string", \
                        help="values: short, long")

    parser.add_option("--whitelist","-w", \
                        action="store", \
                        dest="WHITELIST",\
                        type="string", \
                        help="Checks to be whitelisted")

    parser.add_option("--blacklist","-b", \
                        action="store", \
                        dest="BLACKLIST",\
                        type="string", \
                        help="Checks to be blacklisted")

    parser.add_option("--proxy","-p", \
                        action="store", \
                        dest="PROXY",\
                        type="string", \
                        help="Proxy Server for PatchCheck to access internet in the form: \"server:port\"")

    [options,args] = parser.parse_args()

    global DEBUG
    global WHITELIST
    global BLACKLIST
    global REPORT
    global LISTCHECKS
    global PROXY

    if options.LISTCHECKS:
	LISTCHECKS=options.LISTCHECKS
    if options.DEBUG:
	    DEBUG=options.DEBUG
    if options.WHITELIST :
        WHITELIST = options.WHITELIST.split(',')
    if options.BLACKLIST :
        BLACKLIST = options.BLACKLIST.split(',')
    if options.REPORT:
        REPORT = options.REPORT
    if options.PROXY:
	PROXY = options.PROXY

def main():
	if(os.geteuid() != 0):
	  print ("!WARNING! Some tests require super user privileges, so will be DISABLED in normal user mode !WARNING!");

	# Getting user input
	checkOpts()

	# Initialize checks array
	if (len(WHITELIST)):
	  dprint (1, "Whitelisting: "+str(WHITELIST));
	  for check in WHITELIST:
		clsdef = getattr(sys.modules['__main__'],check);
		checks.append(clsdef());
	else:
		checks.append(UserWithPasswordCheck(UserWithPassword_wl));
		checks.append(FirewallDefaultPolicyCheck());
		checks.append(SSHDConfigCheck());
		checks.append(TCPIPHardeningConfigCheck());
		checks.append(ApacheConfigCheck(Modules_wl));
		checks.append(TomcatConfigCheck(TomcatPath));
		checks.append(FilePermissionsCheck());  
		checks.append(PatchCheck());
		checks.append(PHPConfigCheck());
		
	if LISTCHECKS:
           print ('List of checks:');
           for check in checks:
               print (check.__class__.__name__);
           sys.exit();

	# Execute checks actions
	for check in checks:
	  # Run pre-req
	  check.check_prereq();
	  # Explicitly disable those who are in blacklist
	  if check.__class__.__name__ in BLACKLIST:
		dprint (1,check.__class__.__name__+" in blacklist!");
		check.disable();
	  # Run the check if it is allowed to run
	  if check.isrunnable():
		check.run_check();

	# Collect results
	for check in checks:
	  check.report(REPORT);


if __name__ == '__main__':
    main()


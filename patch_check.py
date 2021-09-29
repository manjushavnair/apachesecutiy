#!/usr/bin/python
from datetime import date, datetime, timedelta
from time import mktime
import sys
import urllib.request

from urllib.request import urlopen

from optparse import OptionParser
from urllib.error  import   HTTPError, URLError
import gzip, mailbox, email, os, sys, re, subprocess, time, errno, platform

# Allowed CentOS releases and their release dates
# Release dates are used to speed up downloads 
# by starting only from the release date.
# Get the release dates from:
# http://en.wikipedia.org/wiki/CentOS#Release_history
centos_release_dates = {}
centos_release_dates[6] = [2011,7]
centos_release_dates[5] = [2007,4]

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

def download_updates(os_ver):
    security_patches = set()
    _begin_year = centos_release_dates[os_ver][0]
    _begin_mon = centos_release_dates[os_ver][1]
    
    try:
        FILE_OUT = open(_out_filename,"w")
    except IOError as (ex_no,ex_str):
        fatal_error("IO Error %(num)s. %(str)s. Unable to write to output file." % {'num':ex_no, 'msg':ex_str})
    
    for year in range(_begin_year,date.today().year+1):
        print ("Processing " + str(year) +", month:"),
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
                if (_remote_file.code == 200):
                    print (mon),
                
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
                    print (str(mon)+"(NOFILE_GOT_HTTP_404)"),
                else:
                    fatal_error("Unknown HTTPError occurred: " + err.strerror)
            except IOError as  err:
                if "CRC check failed" in str(err):
                    # Sometimes proxy server keeps a partial or corrupt file in cache, and sends that to us.
                    # Dont know how to force the proxy to re-download the file from remote host.
                    _msg = "CRC check failed. Probably an issue with file download or proxy? "
                    _msg += "If the download fails with this error for particular month even after retries, then "
                    _msg += "the proxy might be caching a partial or bad file. Try a different proxy."
                    fatal_error(_msg) 
                else:
                    fatal_error("An unhandled IO Error occurred: %(msg)s" % {'msg':err}) 


            except:
                print ("Unknown error occurred.")
                print (sys.exc_info()[0])
                sys.exit(1)
            
            if (mon == 12) or ((year == date.today().year) and (mon == date.today().month)):
                print ("Done.")
            sys.stdout.flush()
            
            _mbox_filename = "/tmp/" + current_date.strftime("%Y-%B.txt")
            try:
                mb = mailbox.mbox(_mbox_filename)
            except (AttributeError):
                mb = mailbox.PortableUnixMailbox(file(_mbox_filename),factory=email.message_from_file)
            except (IOError, e):
                print ("ERROR"+ e)
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
                
                
                if( REGEX_RISK.search(message['subject'])):
                    _risk = REGEX_RISK.search(message['subject']).group(1)
                elif( 'CEBA' in message['subject'] ):
                  _risk = 'Bug'
                
                for line in _body.split("\n"):
                    if (REGEX_RISK_INFO.search(line)):
                        _risk_info += REGEX_RISK_INFO.search(line).group(1)
                    
                    if REGEX_RPMFILENAME.search(line):
                        if REGEX_SPACE.search(line):                        
                            rpm_entry = str(line.split(" ")[-1])
                        elif REGEX_SLASH.search(line):
                            rpm_entry = str(line.split("/")[-1])
                        else:
                            rpm_entry = line
                        
                        _pkg_name = REGEX_RPMFILENAME.search(rpm_entry).group(1) + "." + REGEX_RPMFILENAME.search(rpm_entry).group(4)
                        _pkg_ver = REGEX_RPMFILENAME.search(rpm_entry).group(2) + "-" + REGEX_RPMFILENAME.search(rpm_entry).group(3)
                                            
                        security_patches.add(_pkg_name + "|" + _pkg_ver + "|" + _risk + "|" + _risk_info)
                                
            _FILE_GZ.close()
            _FILE_TXT.close()
            try:
                os.remove("/tmp/" + filename)
                os.remove("/tmp/" + current_date.strftime("%Y-%B.txt"))
            except OSError as e:
                if (e.errno != errno.ENOENT):
                    # This is not 'No such file or directory error'
                    fatal_error( "Unknown error occurred while deleting temp files: " + e.strerror)
            
    for entry in sorted(security_patches):
        FILE_OUT.write(entry + "\n")
    
    FILE_OUT.close()
    sys.stdout.flush()
    
def check_options():
    # Cant have both -c and -u at the same time
    if options.centos_version and options.input_patchlist:
        print ("Error: Cant have both -c and -u options.")
        arg_parser.print_help()
        sys.exit(1)
    
    if options.input_patchlist:
        #Check if the input patchlist file exists
        if not os.path.isfile(options.input_patchlist):
            fatal_error("Error: Patchlist file not found.")
        
        # Is the patchlist os ver same as current system?
        if (options.input_patchlist.split('-')[1].replace('centos','') != platform.dist()[1].split(".")[0] ):           
            fatal_error("Error: OS version in input filename does not match this system version.")
        
        # Is the input patch list too old?
        _date_str = options.input_patchlist.split('-')[-1].split('.')[0]
        _patch_date = datetime(*(time.strptime(_date_str, "%Y%b%d")[0:6]))
        _date_str = date.today().strftime("%Y%b%d")
        _current_date = datetime(*(time.strptime(_date_str, "%Y%b%d")[0:6]))
        date_diff = _current_date - _patch_date
        if date_diff.days > 45:
            fatal_error("Error: Patchlist was generated more than 45 days ago. Create a new one and retry.")
        if date_diff.days < -1:
            # Due to timezone difference, it is possible that sometimes patchlist is one day ahead of system date.
            # But anything more than that is an issue.
            msg = "Error: Patchlist date is (more than 1 day) newer than current system date. "
            msg += "Either patchlist date or system date is incorrect."
            fatal_error(msg)

    if options.centos_version:    
        # These are the centos versions that are accepted.
        # Anything less than 5 is too old. The list is upto 15, so that we dont have to
        # change this part frequently in the coming years.
        if options.centos_version not in centos_release_dates.keys():
            fatal_error("Error: Invalid CentOS version. Only the following CentOS major versions are supported:" + centos_release_dates.keys()) 

def compare_versions(installed_ver, patch_ver):
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
                
        except (ValueError, err):
            continue
                
        if inst_sub_ver > patch_sub_ver:
            return False
        elif inst_sub_ver < patch_sub_ver:
            return True
            
    return False

def check_patches():
    # Get the updated patchlist into a dict
    patched_ver = {}
    
    check_amiversion()
    
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
        fatal_error("yum/repoquery command returned error. The output from yum/repoquery is:\n" + out)
    
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
    pkgs_to_update = ""
    
    for line in installed:
        # remove white space from yum output and use | as the delimiter instead.
        entry = REGEX_SPACES.sub('|', line)
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
              if compare_versions(current_ver, patch[0]):
                strmsg = "Package: " + pkg_name + " Installed: " + current_ver 
                strmsg += " Available Security Update: " + patch[0]
                strmsg += " Risk: " + patch[1] + " URL: " + patch[2].rstrip()
                print (strmsg)
                pkgs_to_update += " " + pkg_name
            
    if pkgs_to_update:
        print ("\n---\nTo install only these packages and avoid installing other updates, run:")
        print (yum_cmd + pkgs_to_update)
        
        if "kernel" in pkgs_to_update:
            _msg = "\n---\nNOTE: The script reports missing patches on other installed kernels, " 
            print (_msg + "even if the presently running kernel is fully patched. Uninstall unwanted kernel packages.")
    else:
        print ("No pending security updates were found." )

def check_internet_connectivity():
    """Exits program if http://lists.centos.org is not reachable."""
    url = "http://lists.centos.org/pipermail/centos-announce/"
    try:
        resp = urlopen(url)
    except:
        fatal_error("Cant connect to lists.centos.org to download updates. Do you have the correct http_proxy environment variable value?")
 
def check_amiversion():
    ami_file = "/etc/centos-release"
    if (os.path.isfile(ami_file)):
        AMI_FILE = open(ami_file,'r')
        for line in AMI_FILE:
            # Format is centos-6-(x86_64|i386)-mmddyyy-(instance|ebs)-(trunk|qa|release)
            _ami_date = date.fromtimestamp(mktime(time.strptime(line.split("-")[3],"%m%d%Y")))
            _today = date.today()
            _diff = _today - _ami_date 
            if (_diff.days > AMI_MAX_LIFETIME ):
                _msg = "WARNING:  AMI used in this system is " + str(_diff.days) + " days old. "
                _msg += "You should switch to a latest AMI as soon as possible."
                print (_msg + "\n---")

def fatal_error(msg):
    print (msg)
    sys.exit(1)
    
if __name__ == '__main__':
    
    arg_parser = OptionParser()
    arg_parser.add_option("--get-updates", "-u", dest="centos_version", type="int",
                          help="The CentOS version (6,5,4,etc) for which mailing list announcements will be downloaded. "+
                          "Patchlist is saved to the current directory. The filename format is patchlist-centosver-currentdate.list. " +
                          "Proxy settings will be taken from environment variable http_proxy.")
    arg_parser.add_option("--patch-check", "-c", dest="input_patchlist",
                          help="Filename containing the latest patch list. Generate the patchlist file using -u option. The filename " +
                          "should be of the same format as generated by -u option. The OS version in the filename should match the "+
                          "current system.")
    
    (options,args) = arg_parser.parse_args()

    check_options()
    
    # If no cmd line options, then download updates and check the system.
    if (not options.centos_version) and (not options.input_patchlist):
        check_internet_connectivity()
            
        _out_filename = "/tmp/patchlist-centos" + platform.dist()[1][0] + date.today().strftime("-%Y%b%d.list")
        
        download_updates(int(platform.dist()[1].split(".")[0]))
        
        print ("---")
        
        try:
            FILE_IN = open(_out_filename,'r')
        except IOError as  (ex_no ,ex_str):
            fatal_error ("IO Error %(num)s: %(msg)s. Unable to read input file." % {'num':ex_no, 'msg':ex_str})

        check_patches()
        
        FILE_IN.close()
        os.remove(_out_filename)
        
    if options.centos_version:
        check_internet_connectivity()
        
        _out_filename = "patchlist-centos" + str(options.centos_version) + date.today().strftime("-%Y%b%d.list")
            
        download_updates(options.centos_version)
        print ("Finished downloading updates. Patchlist file " + _out_filename + " is saved to current directory.")
        
    
    if options.input_patchlist:
        try:
            FILE_IN = open(options.input_patchlist,'r')
        except (IOError, err):
            fatal_error("IO Error: %(msg)s. Unable to read input file." % {'msg':ex_str} )
            
        check_patches()
        FILE_IN.close()
        
    footer_notes = "NOTE: This program can only detect missing patches on CentOS packages from standard CentOS repos or mirrors. " 
    footer_notes += "If you have packages from 3rd party repos like rpmforge or epel, or have installed packages using .tar.gz, compiled from source, or "
    footer_notes += "installed an .rpm downloaded from non-CentOS repo, then this script will not find missing patches."
    
    print ("---\n" + footer_notes + "\n---")
    

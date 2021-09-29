#!/usr/bin/python
import configparser
import threading


import subprocess, socket, sys, os, re, inspect
from optparse import OptionParser

def status_print(loglevel,text, ref="NA"):
    if (loglevel == 'BEGIN') or (loglevel == 'END'):
        print (loglevel + ": " + text)
    else:
        print (loglevel + ": " + text +  " [#REF: "+ ref + "]")
        

def run_httpdchecks(conf, binary, skiplist, risklist):
    httpd_conf = HTTPDConf(conf,binary)
    # Warn if the config file has an entry that does not have corresponding method here.
    for _skiptest in skiplist:
        if "check_"+_skiptest not in dir(httpd_conf):
            status_print("ERROR", "You have a config entry '" + _skiptest + "' that does not have corresponding method in hardening script.")
        else:
            status_print("SKIP", "Skipping test '" + _skiptest + "' as configured in hardening.cfg.")

    for member in inspect.getmembers(httpd_conf, inspect.ismethod):
        # Run all class methods that are not skipped and with names beginning with check_
        if (member[0][0:6] == 'check_') and (member[0][6:] not in skiplist):
            # Set the default risk level to be used by methods if there is no custom configuration.
            _risk = "ERROR"
            
            for _item in risklist:
                if _item[0] == member[0][6:]:
                    # Custom risk is present for this method
                    _risk = _item[1].upper()
                    break
            
            # Run all class methods with default/custom risk rating.
            member[1](_risk)
            

def am_i_root():
    return not os.geteuid()

class HTTPDConf:
    """Class HTTPDConf: Provides utility functions to check various httpd.conf hardening steps."""
    
    # NOTE: *All* method names beginning with check_ will be automatically executed by run_httpdchecks().
    
    def __init__(self,conf, binary):
        status_print("BEGIN", "Beginning Apache httpd.conf checks.")
        #TODO: IO Error handing
        _file = open(conf)
        self.config = _file.readlines()
        _file.close()
        self.binary = binary
    
    def __del__(self):
        status_print("END", "Finished Apache httpd.conf checks.","3.16.2.2")
        
    def check_builtinmodules(self, risk):
        """Check for core modules that are compiled into the httpd binary."""
        compiledin_modules = ("core.c","prefork.c","http_core.c","mod_so.c")
    
        for item in subprocess.getoutput(self.binary + " -l").splitlines()[1:]:
            if item.strip() not in compiledin_modules:
                status_print(risk, "Module " + item.strip() + " is a compiled-in module for Apache binary " + self.binary +
                             ", but is not usually compiled in. (core, prefork, http_core and mod_so are default compiled-in modules).") 

    def check_signaturetoken(self, risk):
        """Checks if Apache leaks too much info in HTTP headers or error pages."""
        _ref = "3.16.3.1"
        
        _regex_servertokens = re.compile(r"^\s*ServerTokens\s+Prod\s*$")
        _regex_serversignature = re.compile(r"^\s*ServerSignature\s+Off\s*$")
        
        if not filter(_regex_servertokens.search, self.config):
            status_print(risk, "'ServerTokens Prod' option is not found in httpd.conf.", _ref)

        if not filter(_regex_serversignature.search, self.config):
            status_print(risk, "'ServerSignature Off' option is not found in httpd.conf.", _ref)
    
    def check_httpauth(self, risk):
        """Checks apache HTTP Authentication configurations."""
        _ref = "3.16.3.2.2"
        _regex_authnfile = re.compile(r"^\s*LoadModule\s+authn_file_module\s+modules/mod_authn_file.so\s*$")
        if filter(_regex_authnfile.search,self.config):
            status_print(risk, "authn_file module is loaded. This is needed only if HTTP Basic auth uses plaintext password files.", _ref)

        _regex_authndbm = re.compile(r"^\s*LoadModule\s+authn_dbm_module\s+modules/mod_authn_dbm.so\s*$")    
        if filter(_regex_authndbm.search, self.config):
            status_print(risk, "authn_dbm module is loaded. This is needed only if HTTP Basic auth uses DBM password files.", _ref)
            
        _regex_authnalias = re.compile(r"^\s*LoadModule\s+authn_alias_module\s+modules/mod_authn_alias.so\s*$")
        if filter(_regex_authnalias.search, self.config):
            status_print(risk, "authn_alias module is loaded. This is needed only if HTTP Basic auth uses aliases.", _ref)

        _regex_authnanon = re.compile(r"^\s*LoadModule\s+authn_anon_module\s+modules/mod_authn_anon.so\s*$")
        if filter(_regex_authnanon.search, self.config):
            status_print(risk, "authn_anon module is loaded. This is needed only if anonymous auth like anon FTP sites is needed.", _ref)

        _regex_authzowner = re.compile(r"^\s*LoadModule\s+authz_owner_module\s+modules/mod_authz_owner.so\s*$")
        if filter(_regex_authzowner.search, self.config):
            status_print(risk, "authz_owner module is loaded. This is needed only if HTTP Basic auth based on file ownership is needed.", _ref)

        _regex_authzdbm = re.compile(r"^\s*LoadModule\s+authz_dbm_module\s+modules/mod_authz_dbm.so\s*$")
        if filter(_regex_authzdbm.search, self.config):
            status_print(risk, "authz_dbm module is loaded. This is needed only if HTTP Basic auth based on group membershipo and using DBM password files.", _ref)
        
        _ref = "3.16.3.2.3"
        _regex_authdigest = re.compile(r"^\s*LoadModule\s+auth_digest_module\s+modules/mod_auth_digest.so\s*$")
        if filter(_regex_authdigest.search, self.config):
            status_print(risk, "auth_digest module is loaded. This is needed only for HTTP Digest auth.", _ref)
    
        _ref = "3.16.3.2.5"
        _regex_ldapmod = re.compile(r"^\s*LoadModule\s+ldap_module\s+modules/mod_ldap.so\s*$")
        if filter(_regex_ldapmod.search, self.config):
            status_print(risk, "ldap module is loaded. This is needed only if HTTP Basic auth uses LDAP.", _ref)

        _regex_authnzldap = re.compile(r"^\s*LoadModule\s+authnz_ldap_module\s+modules/mod_authnz_ldap.so\s*$")
        if filter(_regex_authnzldap.search, self.config):
            status_print(risk, "authnz_ldap module is loaded. This is needed only if HTTP Basic auth uses LDAP.", _ref)

    def check_rewritemodule(self, risk):
        """Checks if modrewrite is enabled."""
        _ref = "3.16.3.2.4"
        _regex_rewritemod = re.compile(r"^\s*LoadModule\s+rewrite_module\s+modules/mod_rewrite.so\s*$")
        if filter(_regex_rewritemod.search, self.config):
            status_print(risk, "rewrite module is loaded. Disable this if the functionality is not needed.", _ref)

    def check_ssi(self, risk):
        """Check if Server Side Includes is enabled."""
        _ref = "3.16.3.2.6"
        _regex_ssi = re.compile(r"^\s*LoadModule\s+include_module\s+modules/mod_include.so\s*$")
        if filter(_regex_ssi.search, self.config):
            status_print(risk, "Server Side Includes (include module) is enabled. Disable this if the functionality" + 
                         " is not needed. If SSI is needed, disable 'exec' by using 'Options IncludesNoExec'.", _ref)

    def check_mimemagic(self, risk):
        """Check if mime magic module is enabled."""
        _ref = "3.16.3.2.7"
        _regex = re.compile(r"^\s*LoadModule\s+mime_magic_module\s+modules/mod_mime_magic.so\s*$")
        if filter(_regex.search, self.config):
            status_print(risk, "Mime magic module provides a second layer of MIME support and can be disabled if not needed.", _ref)

    def check_webdav(self, risk):
        """Check if WebDAV is enabled."""
        _ref = "3.16.3.2.8"
        _regex_dav = re.compile(r"^\s*LoadModule\s+dav_module\s+modules/mod_dav.so\s*$")
        if filter(_regex_dav.search, self.config):
            status_print(risk, "WebDAV (mod_dav) is enabled. Disable this if the functionality is not needed.", _ref)
        
        _regex_davfs = re.compile(r"^\s*LoadModule\s+dav_fs_module\s+modules/mod_dav_fs.so\s*$")
        if filter(_regex_davfs.search, self.config):
            status_print(risk, "WebDAV FS (mod_dav_fs) is enabled. Disable this if the functionality is not needed.", _ref)

    def check_serverstatus(self, risk):
        """Check if server-status and server-info is enabled. By default the status info is available at ourdomain.com/server-status."""
        _ref = "3.16.3.2.9"
        _regex_serverstatus = re.compile(r"^\s*LoadModule\s+status_module\s+modules/mod_status.so\s*$")
        if filter(_regex_serverstatus.search, self.config):
            status_print(risk, "Disable Server Status module (mod_status) if not needed. Otherwise provide proper access control for /server-status.", _ref)

        _ref = "3.16.3.2.10"
        _regex_configdisplay = re.compile(r"^\s*LoadModule\s+info_module\s+modules/mod_info.so\s*$")
        if filter(_regex_configdisplay.search, self.config):
            status_print(risk, "Disable Server Config Info module (mod_info) if not needed. Otherwise provide proper access control for /server-info.", _ref)

    def check_urlspelling(self, risk):
        """Check if correction of misspelled URLs is enabled."""
        _ref = "3.16.3.2.11"
        _regex = re.compile(r"^\s*LoadModule\s+speling_module\s+modules/mod_speling.so\s*$")
        if filter(_regex.search, self.config):
            status_print(risk, "URL spelling correction is enabled. Disable it.", _ref)
    
    def check_httpdinstall(self, risk):
        """Checks apache installation options for security issues."""
        (status,out) = subprocess.getstatusoutput("yum -C list installed httpd")
        if status != 0:
            status_print(risk,"HTTPD binary " + self.binary + " exists, but httpd package is not installed via RPM/yum.")
        
        # Find what user/group is httpd running as. Check the permissions of that user/group.
        _regex = re.compile(r"^\s*(User|Group)\s+.*$")
        for _entry in [item for item in self.config if _regex.search(item)]:
            if _entry.split()[0] == "User":
                _apache_user = _entry.split()[1]
            else:
                _apache_group = _entry.split()[1]
        
        # Check /etc/passwd file for apache user settings
        if (_apache_user == "") or (_apache_group == ""):
            status_print(risk, "Apache User or Group settings not found in httpd.conf")
        else:
            for _line in open("/etc/passwd"):
                if _apache_user+":x:" in _line:
                    _homedir =  _line.split(":")[5]
        if os.path.isdir(_homedir) or (_homedir != "/dev/null"):
            # The home dir should either not exist or be something like /dev/null
            # #REF Apache Security p27.
            _msg = "Apache user home dir is an existing valid directory. A secure option would be to have a non existing home dir or /dev/null"
            status_print(risk, _msg, "#BOOK Apache Security, p27")
            
    def check_userdir(self, risk):
        """Check if user dir URLs are enabled."""
        _ref = "3.16.3.2.12"
        _regex = re.compile(r"^\s*LoadModule\s+userdir_module\s+modules/mod_userdir.so\s*$")
        if filter(_regex.search, self.config):
            status_print(risk, "Disable userdir module if not needed. Web server OS users can be enumerated from network if this is enabled.", _ref)
    
    def check_proxymod(self, risk):
        """Checks if modproxy and its associated modules are enabled."""
        _ref = "3.16.3.2.13"
        _regex = re.compile(r"^\s*LoadModule\s+proxy_module\s+modules/mod_proxy.so\s*$")
        if filter(_regex.search, self.config):
            status_print(risk, "Disable proxy module (mod_proxy) if not needed.", _ref)
            
        _regex = re.compile(r"^\s*LoadModule\s+proxy_balancer_module\s+modules/mod_proxy_balancer.so\s*$")
        if filter(_regex.search, self.config):
            status_print(risk, "Disable proxy balancer module (mod_proxy_balancer) if not needed.", _ref)
        
        _regex = re.compile(r"^\s*LoadModule\s+proxy_ftp_module\s+modules/mod_proxy_ftp.so\s*$")
        if filter(_regex.search, self.config):
            status_print(risk, "Disable proxy ftp module (mod_proxy_ftp) if not needed.", _ref)
        
        _regex = re.compile(r"^\s*LoadModule\s+proxy_http_module\s+modules/mod_proxy_http.so\s*$")
        if filter(_regex.search, self.config):
            status_print(risk, "Disable proxy http module (mod_proxy_http) if not needed.", _ref)

        _regex = re.compile(r"^\s*LoadModule\s+proxy_connect_module\s+modules/mod_proxy_connect.so\s*$")
        if filter(_regex.search, self.config):
            status_print(risk, "Disable proxy connect module (mod_proxy_connect) if not needed.", _ref)

    def check_cachemod(self, risk):
        """Check if cache module and its associated modules are enabled."""
        _ref = "3.16.3.2.14"
        _regex = re.compile(r"^\s*LoadModule\s+cache_module\s+modules/mod_cache.so\s*$")
        if filter(_regex.search, self.config):
            status_print(risk, "Disable cache module (mod_cache) if not needed.", _ref)
        
        _regex = re.compile(r"^\s*LoadModule\s+disk_cache_module\s+modules/mod_disk_cache.so\s*$")
        if filter(_regex.search, self.config):
            status_print(risk, "Disable disk cache module (mod_disk_cache) if not needed.", _ref)

        _regex = re.compile(r"^\s*LoadModule\s+file_cache_module\s+modules/mod_file_cache.so\s*$")
        if filter(_regex.search, self.config):
            status_print(risk, "Disable file cache module (mod_file_cache) if not needed.", _ref)

        _regex = re.compile(r"^\s*LoadModule\s+mem_cache_module\s+modules/mod_mem_cache.so\s*$")
        if filter(_regex.search, self.config):
            status_print(risk, "Disable mem cache module (mod_mem_cache) if not needed.", _ref)
         
    def check_cgimod(self, risk):
        """Check if cgi module is enabled."""
        _ref = "3.16.3.2.15"
        _regex = re.compile(r"^\s*LoadModule\s+cgi_module\s+modules/mod_cgi.so\s*$")
        if filter(_regex.search, self.config):
            status_print(risk, "Disable CGI module (mod_cgi) if not needed.", _ref)
        
        _regex = re.compile(r"^\s*LoadModule\s+env_module\s+modules/mod_env.so\s*$")
        if filter(_regex.search, self.config):
            status_print(risk, "Disable env module (mod_env) if not needed.", _ref)

        _regex = re.compile(r"^\s*LoadModule\s+actions_module\s+modules/mod_actions.so\s*$")
        if filter(_regex.search, self.config):
            status_print(risk, "Disable actions module (mod_actions) if not needed.", _ref)

        _regex = re.compile(r"^\s*LoadModule\s+suexec_module\s+modules/mod_suexec.so\s*$")
        if filter(_regex.search, self.config):
            status_print(risk, "Disable suexec module (mod_suexec) if not needed.", _ref)

    def check_includedconfig(self, risk):
        """Checks if conf.d/*.conf is included. This may be excess configuration."""
        _ref = "3.16.3.3"
        _regex = re.compile(r"^\s*Include\s+conf.d\/\*\.conf\s*$")
        if filter(_regex.search, self.config):
            status_print(risk, "Config 'Include conf.d/*.conf' found. Ensure that there are no unwanted conf file in conf.d/", _ref)

        

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

arg_parser = OptionParser()
arg_parser.add_option("--httpd-binary", dest="httpd_binary", type="string", default="/usr/sbin/httpd",
                      help="Location of httpd binary. The default value is /usr/sbin/httpd. Set this option " + 
                      "if httpd binary is not present in default location.")

arg_parser.add_option("--httpd-conf", dest="httpd_conf",type="string", default="/etc/httpd/conf/httpd.conf",
                      help="Location of the httpd.conf file. The default value is /etc/httpd/conf/httpd.conf.")

(options,args) = arg_parser.parse_args()

if not os.path.isfile(options.httpd_binary):
    status_print("ERROR", "HTTPD binary file " + options.httpd_binary + " does not exist. Set --httpd-binary option to the correct value.")
    sys.exit(1)
    
if not os.path.isfile(options.httpd_conf):
    status_print("ERROR", "HTTPD conf file " + options.httpd_conf + " does not exist. Set --httpd-conf option to the correct value.")

dont_run=[]
custom_risks=[]

if os.path.isfile("./hardening-baseline.cfg"):
    config = configparser.RawConfigParser;
    print("here")
    config.read("./hardening-baseline.cfg")    
    dont_run = [item[0] for item in config.items('ApacheHTTPD') if 'false' in item[1] ]
    custom_risks = [item for item in config.items('ApacheHTTPD') if 'false' not in item[1] ]

run_httpdchecks(options.httpd_conf, options.httpd_binary, dont_run, custom_risks)

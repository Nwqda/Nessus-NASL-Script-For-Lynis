# Author:   Naqwada (RuptureFarm 1029) <naqwada@pm.me>
# License:  MIT License (http://www.opensource.org/licenses/mit-license.php)
# Docs:     https://github.com/Naqwa/Nessus-NASL-Script-for-Lynis.git
# Website:  http://samy.link/
# Linkedin: https://www.linkedin.com/in/samy-younsi/
include("compat.inc");

if (description)
{
  script_id(19113250);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/01");
  script_name(english:"Lynis - Security Auditing Scan");
  script_summary(english:'Typical use cases for Lynis include:\n\n- Security auditing\n- Compliance testing (e.g. PCI, HIPAA, SOx)\n
    - Penetration testing\n- Vulnerability detection\n- System hardening.');
  script_set_attribute(attribute:"synopsis", value:"Lynis is an extensible security audit tool for computer systems running Linux, FreeBSD, macOS, OpenBSD, Solaris, and other Unix derivatives. It assists system administrators and security professionals with scanning a system and its security defenses, with the final goal being system hardening.");
  script_set_attribute(attribute:"description", value:'Lynis scanning is modular and opportunistic. This means it will only use and test the components that it can find, such as the available system tools and its libraries. The benefit is that no installation of other tools is needed, so you can keep your systems clean.\n\n
    Audit steps\nThis is what happens during a typical scan with Lynis:\n1 - Initialization\n2 - Perform basic checks, such as file ownership\n3 - Determine operating system and tools\n4 - Search for available software components\n5 - Check latest Lynis version\n6 - Run enabled plugins\n7 - Run security tests per category\n8 - Perform execution of your custom tests (optional)\n9 - Report status of security scan.');
  script_set_attribute(attribute:"solution", value:"None");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/01");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"agent", value:"unix");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Lynis System Hardening");
  script_copyright(english:"This script is Copyright (C) Shino Corp' and RuptureFarms 1029"); 

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/uname");
  script_timeout(40*60);
  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");
include("ssh_func.inc");

if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS)
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");

uname = get_kb_item_or_exit("Host/uname");
if ("Linux" >!< uname) audit(AUDIT_OS_NOT, "Linux");

if (islocalhost())
{
  if ( ! defined_func("pread") ) exit(1, "'pread()' is not defined.");
  info_t = INFO_LOCAL;
}
else
{
  sock_g = ssh_open_connection(exit_on_disconnect:TRUE);
  if (!sock_g) audit(AUDIT_FN_FAIL, 'ssh_open_connection');
  info_t = INFO_SSH;
}

lynis_version = "3.0.1"; #Update this if necessary.
lynis_directory = "/usr/local/src/lynis-"+lynis_version;
lynis_url = "https://downloads.cisofy.com/lynis/lynis-"+lynis_version+".tar.gz";

#Check if Lynis is already installed on the machine.
cmd = "[ ! -d '"+lynis_directory+"' ] && echo 0";
result = info_send_cmd(cmd:cmd);

#If no Lynis folder let's install it.
if(result)
{
  #Check if internet is availble on the target machine.
  cmd = "ping -c 1 -q google.com >&/dev/null; echo $?";
  result = info_send_cmd(cmd:cmd);
  if(int(result) != 0) 
  {
    security_report_v4(severity:SECURITY_NOTE, port:0, extra:"Error: The target machine is not connected to internet. Please try again.");
    exit(0);
  } 
  cmd = "sudo mkdir -p "+lynis_directory;
  result = info_send_cmd(cmd:cmd);

  if("Permission denied" >< result) security_report_v4(severity:SECURITY_NOTE, port:0, extra:"Error: Could not create Lynis directory ("+lynis_directory+"). Permission denied. Please try again.");


  #Step: download package.

  #Check if wget or curl is installed on the target machine.
  cmd_wget = "[ -x '/usr/bin/wget' ] && echo 1";
  is_wget = info_send_cmd(cmd:cmd_wget);
  cmd_curl = "[ -x '/usr/bin/curl' ] && echo 1";
  is_curl = info_send_cmd(cmd:cmd_curl);

  if(int(is_wget) == 1)
  {
    cmd = "cd "+lynis_directory+" && sudo wget "+ lynis_url + "&& sudo tar xfvz lynis-"+lynis_version+".tar.gz";
  } 
  else if(int(is_curl) == 1)
  {
    cmd = "cd "+lynis_directory+" && sudo curl "+ lynis_url + " -o lynis-"+lynis_version+".tar.gz && sudo tar xfvz lynis-"+lynis_version+".tar.gz";
  } 
  else 
  {
    security_report_v4(severity:SECURITY_NOTE, port:0, extra:"Error: wget and curl are not installed on target machine. Please try again.");
    exit(0);
  }

  result = info_send_cmd(cmd:cmd);
}

#Run Lynis.
cmd = "cd "+lynis_directory+"/lynis/ && sudo ./lynis audit system --quick";
results = info_send_cmd(cmd:cmd, timeout: 2500);

security_report_v4(severity:SECURITY_NOTE, port:0, extra:results);
exit(0);
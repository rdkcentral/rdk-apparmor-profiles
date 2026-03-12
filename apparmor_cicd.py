import argparse
import re
import sys
import os
import difflib
 
g_verbose = False
 
#
# I'm not a fan of doing it this way, but for the sake of simplicity
# maintaining these as globals is easier than dealing with more
# complexity
g_store_exc = False
g_exc_list = []
 
g_priority_dict = { "High": True, "Medium": True, "Low": True }
 
g_skipped_files = []
 
g_violation_filter = None # This in particular is not great
g_display_name = None
 
#
# Basic debug/error functionality
def verboseOut(msg):
    if g_verbose == True:
        print("INFO: " + msg)
 
def errorOut(fatal, msg):
    if fatal:
        print("ERROR: " + msg)
        sys.exit(1)
    else:
        print("WARNING: " + msg)
#
# Each SecurityCheckRule object represents a specific security violation, defined
# later in this file. This is where the rule specific checks are occurring, also
class SecurityCheckRule:
     def __init__(self, objtype, name, rule, msg, raw=False, priority="High"):
         self.objtype = objtype
         self.rule = rule
         self.raw = raw
         self.msg = msg
         self.name = name
         self.priority = priority
 
     def checkRule(self, profile_entry, scheck=None):
         # Check if the rule is just a raw regex
         if self.raw == True or self.rule[0] == None:
             if re.search(self.rule[1], profile_entry):
                 return True
             else:
                 return False
 
         rule_tag = self.rule[0]
         rule_perms = self.rule[1]
         prule_type = self.getProfileType(profile_entry)
 
         # Skip unsupported
         if prule_type == "None":
             if scheck:
                 errorOut(False, f"Unsupported rule type in file {scheck.profile_name}: {profile_entry} ")
             else:
                 errorOut(False, f"Unsupported rule type: {profile_entry}")
             return False
 
        # Files are a special case because they have a more complex
        # rule structure with multiple flags. We allow "tagging" of
        # files to parse these and check for permissions regardless of
        # ordering
        # XXX Add split size cehck
         if prule_type == "File" and self.objtype == "File":
             # Break up file permissions and check against perms
             if rule_tag == "Permissions":
                 perms = profile_entry.lstrip().split()[1]
                 for rule_perm_char in rule_perms:
                     # TODO This doesn't look right
                     if rule_perm_char not in perms:
                         return False
                 return True
 
         else:
             return False
 
     # Return a string identifying the rule type
     def getProfileType(self, rule):
         if not rule:
             errorOut(False, "Empty rule passed to getProfileType")
             return "None"
 
         # These aren't really handled at the moment, but leave
         # the framework in place for them to be detected, at least
         rule = rule.split()
 
         # This probably isn't the most elegant way of handling this, but for now
         # strip out allow/deny/audit prefixes. This maintains the sanity of the
         # rule text for output but doesn't account for more complex detections.
         if rule[0] == "allow" or rule[0] == "deny" or rule[0] == "audit":
             rm = rule.pop(0)
 
         if rule[0] == "capability":
             return "Capability"
         elif rule[0] == "signal":
             return "Signal"
 
         elif rule[0] == "ptrace":
             return "Ptrace"
 
         elif rule[0] == "change_profile":
             return "Change_profile"
 
         elif rule[0] == "mount":
             return "Mount"
 
         elif rule[0] == "umount":
             return "Umount"
 
         elif rule[0] == "network":
             return "Network"
 
         elif rule[0] == "dbus":
             return "Dbus"
 
         elif rule[0].startswith("/"):
             file_perm_list = ['r', 'w', 'm', 'x', 'a', 'c', 'd']
             if len(rule) > 1:
                 perm_result = [ele for ele in file_perm_list if(ele in rule[1])]
             else:
                 perm_result = []
             if rule[0].startswith("/") and bool(perm_result):
                 return "File"
         else:
             return "None"
 
#
# Class representing 1 run of the security checker. Generally, best to make
# this class once per profile.
class SecurityCheck:
     def __init__(self, profile_name, silent=False):
         self.error = False
         self.profile_name = profile_name
         self.violation_count = 0
 
         self.skip_list = [ "{", "}", "#include", "profile " ]
 
         # If this gets any more convoluted, we may just need to add a class for
         # violations
         self.violations = []
         self.violation_filenames = []
         # This is a dict of lists for each entry, so we can support multiples
         # if the same thing is found
         self.violation_dict = {}
 
         self.silent = silent
         return
 
     #
     # We have to skip certain patterns that are not to be examined
     def checkSkipList(self, prule):
         for entry in self.skip_list:
             if prule.startswith(entry):
                 return False # skip
         return True
     #
     # Handle SecurityCheck violation when one is found.
     def failed(self, rule, exe_name, check):
         violation_str = f"""-> Profile filename: {self.profile_name}
            --> Violation name: {check.name}
            --> Violation description: {check.msg}
            --> Priority: {check.priority}
            --> Line: {rule}
            ---> Exception: SecurityException(\"{check.name}\", \"ProfilePath\", \"{self.profile_name}\", \"{check.msg}\", \"<signoff name here>\")
            """
 
         self.violations.append(violation_str)
         self.violation_filenames.append(self.profile_name)
         self.violation_count += 1
 
         violation_key = f"{check.name}:{rule}"
         if violation_key not in self.violation_dict:
             self.violation_dict[violation_key] = []
         self.violation_dict[violation_key].append(violation_str)
 
         return
 
     def normalizeEntry(self, entry):
         return entry.strip().strip(",")
 
     #
     # Run SecurityCheck rules against the list. Errors are delegated to self.failed()
     #
     # @profile_text - The text profile, in full, to be evaluated
     def checkProfile(self, profile_text):
         for prule in profile_text:
             prule = self.normalizeEntry(prule)
             if len(prule) == 0:
                 continue
 
             if self.checkSkipList(prule) == False:
                 continue
 
             for check in check_list:
                 if g_priority_dict[check.priority] == False:
                     continue
 
                 if check.checkRule(prule, self) == True:
                     # Rule match, check for exceptions
                     if self.checkExceptions(prule, check, self.profile_name) == True:
                         # We have an exception or no match, move on
                         continue
                     else:
                         # Rule match, no exception, it's a violation
                         self.failed(prule, "None", check)
                         continue
         return
 
     def checkExceptions(self, rule, check, profile_name):
         # It would be more effective to index them as a dictionary but
         # then we lose the chance to have two named the same, so keep it this way
         #
         # Gather the list of exceptions that match our current name
         named_list = []
         for exc in exception_list:
             if exc.rule_name == check.name:
                 named_list.append(exc)
 
         # Now check them
         #
         # Similar to the check types, the options here will likely need to grow
         # as need for different types of exceptions is found.
         for exc in named_list:
             if exc.exception_type == "ProfilePath":
                 if re.search(exc.exception_regex, profile_name) != None:
                     if g_store_exc:
                         g_exc_list.append(f"Exception: Name='{exc.rule_name}', Profile={profile_name}")
                     return True
             elif exc.exception_type == "FullRegex":
                 for rule in profile.rule_list:
                     if re.search(exc.exception_regex, rule) != None:
                         return True
             else:
                 errorOut(False, "checkExceptions() exception_type is unknown.\n")
                 return False
             return False
         return False
 
#
# These follow this structure
# 0 - Resource type (Capability, File, Ptrace, etc)
# 1 - Name - This must be a unique name for this alert/exception
# 2 - Check - This follows this structure: (CheckType, CheckData), where data is varied depending on what the type is
# 3 - Msg/Desc - Message or description for this alert
# 4 - Raw - Only used if the detection is a raw regex against the entire line (CheckType would be None in this case)
# 5 - Priority - High, Medium, Low, defaults to High if not specified
#
# For example:
#   SecurityCheckRule("File", "FILE_WORX",  ("Permissions", "wx"), "Write/Execute permissions specified", False),
# Creates a rule named FILE_WORX that detects files with the permissions "wx", but does not use raw regular expressions
#   against the entire rule.
#
# The CheckType logic allows us to implement programmatic logic for specific rule segments for more processing. Currently, this
# is only used for file permissions, but could be expanded to other things (e.g. cap types, process full signal lines, etc)
# where regex is less suitable
#
# Add violation rules here
check_list = [
                            SecurityCheckRule("Capability", "CAP_ALL", (None, r"^capability$"), "All capabilities allowed", True),
                            SecurityCheckRule("Capability", "CAP_DACOVERRIDE", (None, r"capability dac_override.*"), "CAP_DAC_OVERRIDE allowed", True, "Low"),
                            SecurityCheckRule("Capability", "CAP_SYSMODULE", (None, r"capability sys_module.*"), "CAP_SYS_MODULE allowed", True, "High"),
                            SecurityCheckRule("Capability", "CAP_SYSADMIN", (None, r"capability sys_admin.*"), "CAP_SYS_ADMIN allowed", True, "Medium"),
                            SecurityCheckRule("File", "FILE_NVRAMEXE", (None, r"^/nvram.* .*ix.*"), "Executable file in nvram", True, "High"),
                            SecurityCheckRule("File", "FILE_NVRAM_MMAP", (None, r"^/nvram.* .*m.*"), "Library file in nvram", True, "High"),
                            SecurityCheckRule("File", "FILE_WMMAPX", ("Permissions", "wm"), "Write/MMAP_PROTECT_EXEC permissions", False, "High"),
                            SecurityCheckRule("File", "FILE_WORX",  ("Permissions", "wx"), "Write/Execute permissions specified", False, "High"),
                            SecurityCheckRule("File", "FILE_ALLDEV",  (None, r".*/dev/\*\*.*"), "/dev/** access granted", False, "Medium"),
                            SecurityCheckRule("File", "FILE_ALLMINIDUMP",  (None, r".*/minidumps/\*.*"), "/minidumps/* access granted", False, "Medium"),
                            SecurityCheckRule("File", "FILE_ETCAPPARMOR_R",  (None, r".*/etc/apparmor.d/\ r.*"), "Full read access to /etc/apparmor.d/", False, "Low"),
                            SecurityCheckRule("File", "FILE_CEDM",  (None, r"/tmp/pqp/\*.*"), "CEDM access", False, "High"),
                            SecurityCheckRule("File", "FILE_EXCESS_X",  (None, r".*/\*\*.*x.*"), "Excessive execute permission wildcards", False, "High"),
                            SecurityCheckRule("File", "FILE_CRONTAB",  (None, r".*/var/spool.*/cron/.*w.*"), "Write access to crontab files", False, "High"),
                            SecurityCheckRule("File", "PROC_ATTR_W", (None, r"^/proc/.*/attr/current .*w.*"), "Write to /proc/<pid>/attr/current", False, "Medium"),
                            SecurityCheckRule("File", "PROC_MAPS", (None, r"/proc/.*/maps.*r.*"), "Read access to all procfs maps files", False, "Low"),
                            SecurityCheckRule("File", "FILE_ALL_LOGS", (None, r"/rdklogs/logs/\*.*"), "Access to all RDK logs", False, "Low"),
                            SecurityCheckRule("File", "FILE_ALL_TMP", (None, r"^(/tmp/.*|/var/(volatile/)?tmp/)\*\w.*"), "Access to all of tmp", False, "Medium"),
                            SecurityCheckRule("File", "FILE_ECRYPTFS", (None, r"^/opt/secure/ECRYPTFS_FNEK_ENCRYPTED.*rw.*"), "Access to all of ecryptfs", False, "High"),
                            SecurityCheckRule(None, "CHANGE_PROFILE", (None, r"change_profile"), "change_profile specified in profile", False, "High"),
                        ]
#
# Define a security exception
# @rule_name - The rule that this exception applies to (e.g. CAPS_ALL)
# @exception_type - What the exception applies to (e.g. a specific line or a whole profile name)
# @exception_rege - Regex to match against the value specified by the type
# @descriptoin - Explain the exception briefly
# @signoff - Name of the person that signed off on the exception
class SecurityException:
     def __init__(self, rule_name, exception_type, exception_regex, description, signoff):
         self.rule_name = rule_name
         self.exception_type = exception_type
         self.exception_regex = exception_regex
         self.desc = description
         self.signoff = signoff
 
         return
 
# Add exceptions here
exception_list = [
 
        ]
 
def __check_file(filename, silent=False):
    # TODO add if exists checks, check against dir
    profile_arr = []
    # Use an explicit display name when provided (e.g. repo path passed from CI),
    # otherwise default to the filesystem filename.
    display_name = g_display_name if g_display_name else filename
    sc = SecurityCheck(display_name, silent)

    isprofile = False
    with open(filename, 'r') as file:
        for line in file:
            profile_arr.append(line)

            # If no profile header is found, skip it, it's something else
            if line.startswith("profile "):
                isprofile = True

    if isprofile == False:
        errorOut(False, f"No profile header found for file {filename}, skipping")
        g_skipped_files.append(filename)
        return None

    sc.checkProfile(profile_arr)

    if sc.violation_count > 0 and g_violation_filter == None:
        # In non-diff (interactive) mode we print summary+details; when called
        # with silent=True (used by diff mode) suppress all printing here so the
        # caller can decide what to display.
        if not silent:
            print("--------------")
            print("Tested file: " + sc.profile_name)

            print("Total violations found in file: " + str(sc.violation_count))
            for v in sc.violations:
                print(v)
    return sc
 
def __check_dir(dirname):
    dir_vcount = 0
    dir_fcount = 0
 
    filtered_results = {}
 
    for entry in os.listdir(dirname):
        path = os.path.join(dirname, entry)
        if os.path.isfile(path):
            result = __check_file(path)
            if(result == None):
                continue
 
            dir_vcount += len(result.violations)
            dir_fcount += 1
 
            if g_violation_filter != None:
                for v in result.violation_filenames:
                    if v in filtered_results:
                        filtered_results[v] += 1
                    else:
                        filtered_results[v] = 1
 
    if g_violation_filter == None:
        print("---------------")
        print("Total files scanned: " + str(dir_fcount))
        print("Total violations found in dir: " + str(dir_vcount))
    else:
        rlen = len(filtered_results)
        print(f"Filtered violation found in {rlen} files")
        for v in filtered_results:
            print(f"  {v} matched {filtered_results[v]} times")
 
def __diff_files(input_file, diff_file):
    # Compare violations by occurrence counts between input_file (new) and diff_file (old)
    input_sc = __check_file(input_file, silent=True)
    diff_sc = __check_file(diff_file, silent=True)

    if input_sc is None:
        # nothing to compare
        return

    # If old file was not parsed, treat it as empty
    if diff_sc is None:
        diff_sc = SecurityCheck(diff_file, silent=True)

    new_only = []
    duplicates_ignored = 0

    # For each violation key in the new file, compare counts
    for vkey, vlist in input_sc.violation_dict.items():
        old_list = diff_sc.violation_dict.get(vkey, [])
        if len(vlist) > len(old_list):
            # difference = extra occurrences introduced in new file
            diff_count = len(vlist) - len(old_list)
            # append the last `diff_count` occurrences from the new list
            new_only.extend(vlist[-diff_count:])
            duplicates_ignored += len(old_list)
        else:
            # nothing new for this key
            duplicates_ignored += len(vlist) if vkey in diff_sc.violation_dict else 0

    # Use display names from parsed SecurityCheck instances when available
    in_name = input_sc.profile_name if input_sc and hasattr(input_sc, 'profile_name') else input_file
    diff_name = diff_sc.profile_name if diff_sc and hasattr(diff_sc, 'profile_name') else diff_file

    print(f"\nViolations introduced in {in_name} (not present or increased in {diff_name}):")
    if len(new_only) == 0:
        print("  (no new violations found)")
        return False

    # Deduplicate identical violation blocks while preserving order
    seen = set()
    unique_results = []
    for r in new_only:
        if r not in seen:
            seen.add(r)
            unique_results.append(r)

    print("--------------")
    print("Tested file: " + in_name)
    print("Total violations found in file: " + str(len(unique_results)))
    for r in unique_results:
        print(r)
    print(f"Total duplicates ignored: {duplicates_ignored}")
    # Indicate to caller that we found new violations
    return len(unique_results) > 0
 
def __output_exc():
    print("----------------")
    print("Exception list: ")
    for exc in g_exc_list:
        print(exc)
 
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Parses AppArmor profiles to identify security violations")
 
    parser.add_argument("-d", "--dir", dest="input_dir", help="Specify a whole directory to scan.")
    parser.add_argument("-f", "--f", dest="input_file", help="Scan a specific file.")
    parser.add_argument("-a", "--a", dest="diff_file", help="Compare two results and remove entries that exist in both (diff)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output.")
    parser.add_argument("-e", "--print_exceptions", action="store_true", help="Output exception matches.")
 
    # -c is confusing but -h conflicts with --help
    parser.add_argument("-c", "--exclude_high", action="store_true", help="Exclude all high priority entries.")
    parser.add_argument("-m", "--exclude_med", action="store_true", help="Exclude all medium priority entries.")
    parser.add_argument("-l", "--exclude_low", action="store_true", help="Exclude all low priority entries.")
 
    parser.add_argument("-s", "--sole_violation", dest="sole_violation", help="Specify a specific violation ID to search.")
    parser.add_argument("-N", "--display-name", dest="display_name", help="Display name to use for the input file (useful when passing temp files)")
 
    args = parser.parse_args()
 
    g_store_exc = args.print_exceptions
 
    # Filter out priorities that were requested for exclusion
    if args.exclude_high:
         g_priority_dict["High"] = False
    if args.exclude_med:
         g_priority_dict["Medium"] = False
    if args.exclude_low:
         g_priority_dict["Low"] = False
 
    # Verify -s entry exists, then filter it out
    if args.sole_violation:
        found = False
        for entry in check_list:
            if entry.name == args.sole_violation:
                found = True
                # Yuck
                check_list = []
                check_list.append(entry)
                break
 
        if found == False:
            errorOut(False, "SecurityCheck name passed in via -s not found in check_list.")
 
        g_violation_filter = args.sole_violation
 
    if args.input_file and not args.diff_file:
        __check_file(args.input_file)
    elif args.input_dir:
        __check_dir(args.input_dir)
    elif args.diff_file:
        # If a display name was provided, stash it for use when parsing temp files
        if args.display_name:
            g_display_name = args.display_name

        found = __diff_files(args.input_file, args.diff_file)
        if found:
            sys.exit(1)
 
    if args.print_exceptions:
        __output_exc()
 
    if len(g_skipped_files) > 0:
        print("---------------")
        print("Skipped files due to missing profile header: ")
        for entry in g_skipped_files:
            print(" " + entry)
 
    print("")
    if(g_priority_dict["High"] == False):
        print("High priority results excluded.")
    if(g_priority_dict["Medium"] == False):
        print("Medium priority results excluded.")
    if(g_priority_dict["Low"] == False):
        print("Low priority results excluded.")

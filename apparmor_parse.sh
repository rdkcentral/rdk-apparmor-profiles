#!/bin/sh

##########################################################################
# If not stated otherwise in this file or this component's LICENSE
# file the following copyright and licenses apply:
#
# Copyright 2024 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################

Apparmor_defaults="/etc/apparmor/apparmor_defaults"
Apparmor_blocklist="/opt/secure/Apparmor_blocklist"
PROFILES_DIR="/etc/apparmor/binprofiles/*/"
PARSER="/sbin/apparmor_parser"
SYSFS_AA_PATH="/sys/kernel/security/apparmor/profiles"
RDKLOGS="/opt/logs/startup_stdout_log.txt"

if [ -f /lib/rdk/apparmor_utils.sh ]; then
    source /lib/rdk/apparmor_utils.sh
fi

if [ -f /lib/rdk/t2Shared_api.sh ]; then
    source /lib/rdk/t2Shared_api.sh
fi

if [ ! -f $Apparmor_blocklist ]; then
    touch $Apparmor_blocklist
fi

complain_list=()
enforce_list=()
#                                      
# Parse the blocklist into block_modes_<process name>
# We do this due to BusyBox lacking associative
# arrays.                                              
while IFS=: read -r process mode; do
  [[ -z $process || $process == \#* ]] && continue
  # These are eval'd so we have to be careful with the
  # contents.         
  if [[ ! "$mode" =~ disable|complain|enforce ]]; then
    echo "Invalid blocklist mode for process $process, ignoring"  
    continue                       
  fi                            
  
  if [[ ! $process =~ ^[[:alnum:]_.-]+$ ]]; then
    echo "Process blocklist name is invalid, ignoring"
    continue                    
  fi

  eval "block_modes_${process//./_}=${mode}"
done < "$Apparmor_blocklist"            
                                             
#                                          
# Parse the defaults file, load arrays based on the                      
# values in the defaults file compared to the blocklist
while IFS=: read -r process mode; do
  [[ -z $process || -z $mode ]] && continue
                                  
  if [[ ! $process =~ ^[[:alnum:]_.-]+$ ]]; then
    echo "Process defaults name is invalid, ignoring"
    continue                       
  fi
                                     
  eval "var_name=block_modes_${process//./_}"
  if [[ ! $var_name =~ ^[[:alnum:]_.-]+$ ]]; then
    echo "Var name is invalid, ignoring"
    continue                                     
  fi                
        
  eval "blocklist_mode=\${block_modes_${process//./_}}"
  if [[ -z $blocklist_mode ]]; then
     blocklist_mode=$mode                        
  fi
  
  if [ "$mode" == "enforce" ]; then
        if [ "$blocklist_mode" == "complain" ]; then
              profile_file_complain="/etc/apparmor.d/*$process"
              complain_list+=("$profile_file_complain")
        elif [ "$blocklist_mode" != "disable" ]; then
               profile_file_enforce="$PROFILES_DIR/*$process"
               enforce_list+=("$profile_file_enforce")
        fi
  elif [ "$mode" == "complain" ] && [ "$blocklist_mode" != "disable" ]; then
           profile_file_complain="/etc/apparmor.d/*$process"
           complain_list+=("$profile_file_complain")
  fi                                 
done < "$Apparmor_defaults"

if [[ ${#complain_list[@]} -gt 0 ]]; then
    joined_string=$(IFS=" "; echo "${complain_list[*]}")
    apparmor_parser -rWC $joined_string
fi

if [[ ${#enforce_list[@]} -gt 0 ]]; then
    joined_string=$(IFS=" "; echo "${enforce_list[*]}")
    apparmor_parser -rWB $joined_string
fi

if type systemd_apparmor; then
    systemd_apparmor
fi

list=`cat $SYSFS_AA_PATH | grep complain | awk '{print $1}' | tr '\n'  ','`
cnt=`cat $SYSFS_AA_PATH | grep complain | wc -l`
if [ ! -z "$list" ]; then
     echo "List of profiles in Apparmor-complain mode:$cnt : $list" >> $RDKLOGS
     t2ValNotify "APPARMOR_C_split:" "$cnt,$list"
fi

list=`cat $SYSFS_AA_PATH | grep enforce | awk '{print $1}' | tr '\n'  ','`
cnt=`cat $SYSFS_AA_PATH | grep enforce | wc -l`
if [ ! -z "$list" ]; then
     echo "List of profiles in Apparmor-enforce mode:$cnt : $list"  >> $RDKLOGS
     t2ValNotify "APPARMOR_E_split:" "$cnt,$list"
fi

if type apparmor_telemetry; then
    apparmor_telemetry
fi

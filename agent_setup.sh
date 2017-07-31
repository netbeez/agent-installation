#!/bin/bash

# Netbeez
# Sets an Agent up to communicate with a Dashboard
# Agent -> request config -> central server -> config -> Agent
# find <<<MAIN>>> at the bottom of the file

set -e # exit all shells if script fails


# ###################################################################################################################################################
# ###################################################################################################################################################
# ###################################################################################################################################################
# GLOBAL CONSTANTS AND GETOPTS # ####################################################################################################################
# ###################################################################################################################################################
# ###################################################################################################################################################
# ###################################################################################################################################################

# ##################### GLOBAL VARIABLE DICTIONARY #################################################################################################
# SECRET
# > the secret string given to the user to associate an agent with a dashboard
# IS_HELP
# > displays usage, which explains how to use this script
# IS_DEV
# > a hidden parameter (undocumented in usage) that changes some functionality for dev work
# ERROR
# > stores an integer 1, which indicates an error
# PASS
# > stores an integer 0, which indicates a successful action
# PROGRAM
# > the name of this program
# PROMPT_SPACE
# > used to wrap some user prompts so they are more easily noticable
# LOG_FILE
# > the log file for this script


declare -ri ERROR=1;
declare -ri PASS=0;
declare -r PROGRAM="$0";
declare -r SCRIPT_ARGS="$@";
declare -r LOG_FILE="/tmp/agent_setup.log";
declare -r BLACKLIST_FILE="/etc/modprobe.d/raspi-blacklist.conf";
declare -r PROMPT_SPACER=">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>";

function initialize_input(){
    local -r args="$@";
    
    local secret="";
    local is_dev="false";
    local is_help="false";
    
    local is_modify_interface="false";
    local is_fetch_ims_config="false";
    local is_install_agent_software="false";
    local is_full_install="true";


    local OPTS=$(getopt -o dish --long ,secret:,modify-interface,fetch-ims-config,install-agent-software,dev,help -- "$@");
    eval set -- "$OPTS";
    while true ; do
        case "$1" in
            --secret) 
                secret=$2;
                shift 2;
                ;;
            --dev)
                is_dev=true;
                shift 1
                ;;
            --modify-interface)
                is_modify_interface="true";
                is_full_install="false";
                shift 1;
                ;;
            --fetch-ims-config)
                is_fetch_ims_config="true";
                is_full_install="false";
                shift 1;
                ;;
            --install-agent-software)
                is_install_agent_software="true";
                is_full_install="false";
                shift 1;
                ;;                
            --help)
                is_help=true;
                shift 1;
                ;;
            *)
                break;
                ;;
        esac
    done;
    
    if [[ "$is_full_install" == "true "]]; then
      is_fetch_ims_config="true";
      is_install_agent_software="true";
    fi
    

    readonly SECRET="$secret";
    readonly IS_HELP="$is_help";
    readonly IS_DEV="$is_dev";
    readonly IS_INTERFACE_SETUP="$is_modify_interface";
    readonly IS_FETCH_IMS_CONFIG="$is_fetch_ims_config";
    readonly IS_INSTALL_AGENT_SOFTWARE="$is_install_agent_software";
    
    # readonly IS_ALL="$is_all";
    

}



# ###################################################################################################################################################
# ###################################################################################################################################################
# ###################################################################################################################################################
# GLOBAL LOGGING FUNCTIONS # ########################################################################################################################
# ###################################################################################################################################################
# ###################################################################################################################################################
# ###################################################################################################################################################

# base logging functoins
function log(){
  local -r msg="$1"
  printf "$msg\n\n" >> "$LOG_FILE"
}


# logs to file and echos to console
function echo_and_log(){
  local -r msg="$1"
  log "$msg"
  echo "$msg"
}


# prepends error to message
function error_log(){
  local -r msg="$1"
  log "ERROR: $msg"
}


# prepends warning to message
function warning_log(){
  local -r msg="$1"
  log "WARNING: $msg"
}


# something blew up, this exits the script with some additional information
function error_exit(){
  local -r msg="$1"
  error_log "EXITING SCRIPT: $msg"
  error_log "EXITING SCRIPT: If you're stuck, contact support@netbeez.net"
  exit "$ERROR"
}




# ###################################################################################################################################################
# ###################################################################################################################################################
# ###################################################################################################################################################
# GLOBAL MISC. FUNCTIONS # ##########################################################################################################################
# ###################################################################################################################################################
# ###################################################################################################################################################
# ###################################################################################################################################################

# displays usage information to the user for this script
function usage(){
  # http://docopt.org
  echo "----------------------------------------------------------------------------------------------------"
  echo "Usage: $PROGRAM ( --secret=<key> | --modify-interface | --help )"
  echo
  echo "###### General Options "
  echo "       --secret=<key>              the secret key given to you from Netbeez (usually via email)"
  echo 
  echo "       --help                      displays this usage page"
  echo 
  echo "###### Raspberry Pi 3 **Only** Options "
  echo "       --modify-interface          modifies the interface used (wireless or wired) without any additional setup"
  echo
  echo "###### Developer Options"
  echo "###### NOTICE: do *NOT* use these unless instructed to by Netbeez support"
  echo
  echo "       --fetch-ims-config          explicitly fetch configuration files without any additional setup"
  echo
  echo "       --install-agent-software    explicitly installs Netbeez software without any additional setup"
  echo
  echo "###### More Information"
  echo "       Agent Install       https://netbeez.zendesk.com/hc/en-us/articles/207989403-Install-NetBeez-agents-All-versions-"
  echo "       Documentation       http://docopt.org"
  echo "----------------------------------------------------------------------------------------------------"

}




# print some info about this machine
function print_machine_information(){
  clear

  echo
  echo
  echo

  echo_and_log ">>>>>>>>>>>>>>>>>>> MACHINE INFORMATION "

  # is rpi3 3?
  if [[ $(is_rpi_3_agent) == "true" ]]; then
    echo_and_log "DETECTED HARDWARE: Raspberry Pi3 "
  else
    echo_and_log "DETECTED HARDWARE: **not** Raspberry Pi"
  fi

  # is software agent?
  if [[ $(is_software_agent) == "true" ]]; then
    echo_and_log "DETECTED AGENT TYPE: software agent"
  else
    echo_and_log "DETECTED AGENT TYPE: **not** software agent"
  fi

  # print architecture
  echo_and_log "DETECTED ARCHITECTURE: $(uname -m)"

  echo_and_log ">>>>>>>>>>>>>>>>>>> MACHINE INFORMATION "

  echo
  echo
  echo

}


# checks for valid flags given to this script
function check_input(){
  # checks parsed parameters
  # if any of the parameter options are 
  # > invalid a usage will be displayed
  local is_usage=false

  log "checking the user input"

  # check if the user wants help
  if [[ "$IS_HELP" == "true" ]]; then
    is_usage=true

  elif [[ "$SECRET" == "" && "$IS_INTERFACE_SETUP" == "false" && "$IS_HELP" == "false" ]]; then
    echo
    echo
    echo_and_log "ERROR: MUST give one of the following flags: --secret=<your_secret> *or* --modify-interface"
    echo
    echo
    is_usage=true

  elif [[ "$IS_INTERFACE_SETUP" == "true" && $(is_rpi_3_agent) == "false" ]]; then
    echo
    echo
    echo_and_log "ERROR: CANNOT modify interface unless agent is a Raspberry Pi 3"
    echo
    echo
    is_usage=true

  fi


  # if usage is true, then display usage and exit
  if [[ "$is_usage" == true ]]; then
    usage
    exit "$ERROR"
  fi
}


function _return(){
  local -r return_value="$1"
  echo "$return_value"
}




# ###################################################################################################################################################
# ###################################################################################################################################################
# ###################################################################################################################################################
# GLOBAL HARDWARE FUNCTIONS # #######################################################################################################################
# ###################################################################################################################################################
# ###################################################################################################################################################
# ###################################################################################################################################################

# is this a "software" agent
function is_software_agent(){
  local status=false
  if [[ $(is_image_agent) != true ]]; then
    status=true
  fi
  _return $status
}


# is this an "image" agent
function is_image_agent(){
  local status=false
  if [[ -d "/usr/local/netbeez" ]]; then
    status=true
  fi
  _return $status
}


# is this a raspberry pi 3 agent -- checks the mac oui and a model file present on the system
function is_rpi_3_agent(){
  local status="false"
  # local -r address_file="/sys/class/net/wlan0/address"  

  if [ -f $address_file ]; then
    # local -r rpi_3_architecture="arm8"
    # local -r mac_address=$(cat $address_file)
    # local -r rpi_oui="b8:27:eb"    
    local -r rpi_3_model="Raspberry Pi 3"
    local -r model_file="/sys/firmware/devicetree/base/model"

    # if [[ $mac_address =~ $rpi_oui && $(cat /sys/firmware/devicetree/base/model | grep "$rpi_3_model") ]]; then
    if [[ -f "$model_file" && $(cat $model_file | grep "$rpi_3_model") ]]; then
      status="true"
    fi
  fi
  
  _return "$status"
}


# resters the agent processes based on agent type
function restart_agent_process(){
  # Restart the agent process
  echo_and_log "RESTARTING the Netbeez Agent process"

  if [[ $(is_software_agent) == "true" ]]; then
    sudo service netbeez-agent stop
    sudo service netbeez-agent start
  else
    sudo service nbagent_prod stop
    sudo service nbagent_prod start
  fi
}


# # compare the backed-up blacklist file with the current -- did it change
function is_blacklist_changed(){
  local is_changed=false

  # if the backup files exists and diff the backup with the current
  if [[ -f "$BLACKLIST_FILE.bak" && $(diff $BLACKLIST_FILE $BLACKLIST_FILE.bak) ]]; then
    is_changed=true
  fi

  _return "$is_changed"
}



# ###################################################################################################################################################
# ###################################################################################################################################################
# ###################################################################################################################################################
# SELF_CONFIGURE SUBSHELL # #########################################################################################################################
# ###################################################################################################################################################
# ###################################################################################################################################################
# ###################################################################################################################################################
# the agent will configure itself from the ims
function module::fetch_ims_configuration()(
  # ##################### SELF_CONFIGURE VARIABLE DICTIONARY ########################################################################################
  # CONFIG_FOLDER
  # > directory that contains a config file (for connecting to a dashboard) and a pem file
  # CONFIG_FILE
  # > config file for connecting to the dashboard
  # AGENT_PEM_FILE
  # > pem file for connecting to the dashboard
  # URL
  # > the base ims url 
  # > when IS_DEV=true this url is changed to a local vagrant IMS instance ip
  # END_POINT
  # > the actual endpoint url to poll for configuration information
  # IMS_URL
  # > URL+END_POINT

  # # config directory and files
  declare -r CONFIG_FOLDER="/etc/netbeez"           
  declare -r CONFIG_FILE="netbeez-agent.conf"       
  declare -r AGENT_PEM_FILE="netbeez-agent.pem"     
  declare URL="https://ims.netbeez.net/"  
  # # IMS stuff
  if [[ "$IS_DEV" == "true" ]]; then
    declare URL="https://192.168.33.8/"   
  fi
  declare -r URL
  declare -r END_POINT="apis/v1/agent_setup"
  declare -r IMS_URL="$URL$END_POINT"


  
  # JSON: finds the value of a key
  function find_value_by_key(){
    # ###################
    # awk sets RS and FS so that 'k1:v1,...,kn:vn' is
    # "formatted" into a 2D table
    # then matches the key/$1 and prints value/$2
    # ###################
    local -r key="$1"
    local -r json="$2"

    local -r value=$(printf "$json" | awk -v key="\"$key\"" 'BEGIN{ RS=","; FS=":"; }; $1 ~ key {print $2}' | sed 's/"//g')

    _return "$value"
  }


  # tries to write some data to a location on disk
  function write_to_disk(){
    # writes data to disk
    local -r data="$1"
    local -r location="$2"

    sudo bash -c "echo \"$data\" > \"$location\""
  }


  # tries to write some data to a location on disk (fallback for write_to_disk function)
  function write_to_disk_fallback_1(){
    # writes data to disk
    local -r data="$1"
    local -r location="$2"

    echo -n "$data" > "$location"
  }


  # tries to write some data to a location on disk (fallback for write_to_disk_fallback_1 function)
  function write_to_disk_fallback_2(){
    # writes data to disk
    local -r data="$1"
    local -r location="$2"

    echo "$data" > "$location"
  }


  # compares the md5 of a file on disk with a given md5 string
  function verify_md5(){
    local status=$ERROR
    log "verifying the md5 of a file"
    # this verifies md5s for a file on disk
    # > create new md5: new_md5 = md5(file_on_disk)
    # > then compare: new_md5 == given_md5
    local -r check_me="$1"
    local -r given_md5=$(echo "$2" | cut -d' ' -f1)
    local -r new_md5=$(md5sum "$check_me" | cut -d' ' -f1)
    # new_md5="hello wrold" #this is used to test failed md5s

    local -r result=$(echo "$given_md5" | grep "$new_md5")
    # echo "$result"
    if [[ "$result" == "" ]]; then
      status=$PASS
    fi

    _return $status
  }


  # writes the agent pem file (uses fallbacks and checks md5s)
  function write_agent_pem(){
    # 1. writes agent_pem to disk
    # 2. verifies the integrity of agent_pem
    # 3. moves agent_pem to proper location
    local -r netbeez_agent_pem="$1"
    local -r netbeez_agent_pem_md5="$2"

    log "VERIFYING key integrity"

    mkdir -p "$CONFIG_FOLDER"

    ##############################################################
    ## FIRST TRY: WRITE AGENT PEM TO DISK AND VERIFY MD5
    write_to_disk "$netbeez_agent_pem" "$CONFIG_FOLDER/$AGENT_PEM_FILE"
    local is_okay=$(verify_md5 "$CONFIG_FOLDER/$AGENT_PEM_FILE" "$netbeez_agent_pem_md5")
    if [[ "$is_okay" == "$PASS" ]]; then
      log "INITIAL AGENT PEM WRITE SUCCEEDED"
      return 0
    fi

    ##############################################################
    ## FALLBACK 1: WRITE AGENT PEM TO DISK AND VERIFY MD5
    warning_log "the initial key write failed - trying fallback method 1"

    write_to_disk_fallback_1 "$netbeez_agent_pem" "$CONFIG_FOLDER/$AGENT_PEM_FILE"
    local is_okay=$(verify_md5 "$CONFIG_FOLDER/$AGENT_PEM_FILE" "$netbeez_agent_pem_md5")
    if [[ "$is_okay" == "$PASS" ]]; then
      log "FALLBACK 1 AGENT PEM WRITE SUCCEEDED"
      return 0
    fi

    ##############################################################
    ## FALLBACK 2: WRITE AGENT PEM TO DISK AND VERIFY MD5
    warning_log "the first fallback key write method failed - trying fallback method 2"

    write_to_disk_fallback_2 "$netbeez_agent_pem" "$CONFIG_FOLDER/$AGENT_PEM_FILE"
    local is_okay=$(verify_md5 "$CONFIG_FOLDER/$AGENT_PEM_FILE" "$netbeez_agent_pem_md5")
    if [[ "$is_okay" == "$PASS" ]]; then
      log "FALLBACK 2\ AGENT PEM WRITE SUCCEEDED"
      return 0
    fi

    error_exit "THE key could not be verified"
  }


  # requests config data from the ims
  function request_config_data(){
    log "making curl request to Netbeez at $IMS_URL"
    #get config data from the ims
    local -r response_json=$(curl --silent \
                --request POST "$IMS_URL" \
                --insecure \
                --data "secret=$SECRET" \
                | sed 's/{\|}//g' )

    _return "$response_json"
  }


  # checks the returned server values to see if they are valid (ie. not empty)
  function check_result(){
    # if any of parsed server values are empty, then something went wrong
    # if we have a message from the server then it at least got that far
    local -r result="$1"
    local -r server_message="$2"
    if [[ "$result" == "" && "$server_message" == "" ]]; then
      error_exit "UNKNOWN ERROR: something went wrong with the request. Please try again."
    elif [[ "$result" == "" ]]; then
      error_exit "$server_message"
    fi
  }


  # checks desired JSON key/values for validity
  function validate_values_from_ims(){
    local -r server_message="$1"
    local -r host="$2"
    local -r secure_port="$3"
    local -r interface="$4"
    local -r netbeez_agent_pem="$5"
    local -r netbeez_agent_pem_md5="$6"
    
    log "validating <host>: $host"
    check_result "$host" "$server_message"

    log "validating <server port>: $secure_port"
    check_result "$secure_port" "$server_message"

    log "validating <interface>: $interface"
    check_result "$interface" "$server_message"

    log "validating <netbeez_agent.pem>: (not printing for security)"
    check_result "$netbeez_agent_pem" "$server_message"

    log "validating <netbeez_agent.pem.md5>: $netbeez_agent_pem_md5"
    check_result "$netbeez_agent_pem_md5" "$server_message"

    log "validating the server response message: $server_message"
    check_result "$server_message" "$server_message"
  }


  # backup the config file just in case
  # if this config file isn't here there's something wrong with this install
  function backup_config_file(){
    if [[ ! -f "$CONFIG_FOLDER/$CONFIG_FILE" ]]; then
      error_exit "CONFIG file ($CONFIG_FOLDER/$CONFIG_FILE) does not exist. Something went wrong during the installation."
    else
      cp "$CONFIG_FOLDER/$CONFIG_FILE" "$CONFIG_FOLDER/$CONFIG_FILE.bak"
    fi
  }


  # update the config file with new information
  function update_config_file(){
    log "updating the $CONFIG_FOLDER/$CONFIG_FILE config file"
    #ex. {"host":"hostname.netbeezcloud.net", "secure_port":"20018", "interfaces":"eth0", "model":"software-debian"}
    local -r host="$1"
    local -r secure_port="$2"
    local -r interface="$3"
    # parse model from current config file
    local -r config_data=$(cat "$CONFIG_FOLDER/$CONFIG_FILE" | sed 's/{\|}//g')
    local -r model=$(find_value_by_key "model" "$config_data")
    # create config file
    local -r config='{\"host\":\"'"$host"'\", \"secure_port\":\"'"$secure_port"'\", \"model\":\"'"$model"'\"}'
    # write it
    write_to_disk "$config" "$CONFIG_FOLDER/$CONFIG_FILE"
  }


  # ########################################
  # ########################################
  function main(){
    log "CONFIGURING AGENT FROM NETBEEZ SERVER"
    # this function will self configure an agent
    # from info contained on the IMS
    echo_and_log "CONFIGURING Netbeez Agent from Netbeez Server"

    log "BEGINNING to self-configure this agent"
    
    # does the required config file exist
    backup_config_file
    
    # REQUEST DATA
    echo_and_log "REQUESTING information from Netbeez"
    local -r ims_config=$(request_config_data)
    
    # PARSE DATA
    log "parsing information from Netbeez"
    local -r host=$(find_value_by_key "host" "$ims_config")
    local -r secure_port=$(find_value_by_key "secure_port" "$ims_config")
    local -r interface=$(find_value_by_key "interface" "$ims_config")
    local -r netbeez_agent_pem=$(find_value_by_key "netbeez_agent_pem" "$ims_config")
    local -r netbeez_agent_pem_md5=$(find_value_by_key "netbeez_agent_pem_md5" "$ims_config")
    local -r server_message=$(find_value_by_key "msg" "$ims_config")

    # CHECK RESULTS
    echo_and_log "VALIDATING the results from Netbeez"
    validate_values_from_ims "$server_message" "$host" "$secure_port" "$interface" "$netbeez_agent_pem" "$netbeez_agent_pem_md5" 

    # VERIFY KEY
    echo_and_log "UPDATING agent with Netbeez Server information"
    write_agent_pem "$netbeez_agent_pem" "$netbeez_agent_pem_md5"
    update_config_file "$host" "$secure_port" "$interface"
  }
  main
  # ########################################
  # ########################################
)







# ###################################################################################################################################################
# ###################################################################################################################################################
# ###################################################################################################################################################
# SOFTWARE AGENT INITIALIZATION SUBSHELL # ##########################################################################################################
# ###################################################################################################################################################
# ###################################################################################################################################################
# ###################################################################################################################################################
function module::initialize_software_agent()(
  # https://netbeez.zendesk.com/hc/en-us/articles/207989403-Install-NetBeez-agents-All-versions-

  # add the netbeez repo server to apt-get based on cpu architecture 
  function add_netbeez_repo_source(){
    # Add the NetBeez software repository, update the database, and install the netbeez-agent package:
    if [ $(uname -m) == "x86_64" ]; then
    	log "TYPE IS x86"
    	echo "deb [arch=amd64] http://repo.netbeez.net wheezy main" | \
      		tee /etc/apt/sources.list.d/netbeez.list
    else
    	log "TYPE IS $(uname -m)"
    	echo "deb http://repo.netbeez.net wheezy main" | \
      		tee /etc/apt/sources.list.d/netbeez.list
    fi
  }


  # install the netbeez agent software
  function install_netbeez_agent(){
    wget -O - http://repo.netbeez.net/netbeez_pub.key | apt-key add -
    apt-get update
    apt-get install netbeez-agent -y
  }


  # ########################################
  # ########################################
  function main(){
    # this function will add netbeez repos
    # > get config info from the ims
    # > then restart the agent process
    echo_and_log "ADDING Netbeez repos"
    add_netbeez_repo_source

    echo_and_log "INSTALLING Netbeez Agent software"
    install_netbeez_agent
  }
  main
  # ########################################
  # ########################################
)




# ###################################################################################################################################################
# ###################################################################################################################################################
# ###################################################################################################################################################
# SOFTWARE AGENT INITIALIZATION SUBSHELL # ##########################################################################################################
# ###################################################################################################################################################
# ###################################################################################################################################################
# ###################################################################################################################################################

function module::initialize_rpi_3()(
  # ##################### RPI_3_INIT VARIABLE DICTIONARY ############################################################################################
  # DISABLED_WIRELESS_WRAPPER_STRING
  # > wraps the disable wireless configuration instructions so when re-enabling all the blacklist instructions can
  # > easily be regex'd out
  # BLACKLIST_FILE
  # > the file where blacklist information is written

  declare -r DISABLED_WIRELESS_WRAPPER_STRING="# ############################ WRITTEN BY NETBEEZ agent_setup.sh"
  

  # backup the blacklist file
  function backup_blacklist_file(){
    cp -a "$BLACKLIST_FILE" "$BLACKLIST_FILE.bak"
  }


  # blacklist the rpi3 wireless card
  function blacklist_wireless_card(){
    log "appending disable wifi text to $BLACKLIST_FILE"

    backup_blacklist_file

    local -ra appendString=(
      "$DISABLED_WIRELESS_WRAPPER_STRING"
      "#wifi"
      " blacklist brcmfmac"
      " blacklist brcmutil"
      ""
      "#bt"
      " blacklist btbcm"
      " blacklist hci_uart"
      "$DISABLED_WIRELESS_WRAPPER_STRING"
    )
    ( IFS=$'\n'; echo "${appendString[*]}" >> "$BLACKLIST_FILE" )
  }


  # unblacklist the rpi3 wireless card
  function unblacklist_wireless_card(){
    backup_blacklist_file
    # remove the blacklist lines between (and including) the DISABLED_WIRELESS_WRAPPER_STRING
    sed --in-place '/'"$DISABLED_WIRELESS_WRAPPER_STRING"'/,/'"$DISABLED_WIRELESS_WRAPPER_STRING"'/d' "$BLACKLIST_FILE"
  }

  # prompt the user to disable the rpi3 onboard wireless card
  function prompt_disable_wireless(){
    local -r yes_response="y"
    local -r no_response="n"
    local is_done=false
    local response=""
    
    while [ $is_done == false ]; do
      echo "It looks this machine is a Raspberry Pi 3."
      echo "Would you like to disable (via blacklist) the **ONBOARD** wireless network interface? (y/n)"
      echo "WARNING: this will reboot your Raspberry Pi 3 automatically"

      read response

      if [[ $response == $yes_response ]]; then
        echo
        echo "IMPORTANT! The onboard wireless will be disabled."
        echo "IMPORTANT! You may want to take note of this."
        echo "IMPORTANT! TO RUN INTERFACE CONFIGURATION AGAIN USE THE FLAG --modify-interface"

        blacklist_wireless_card

        is_done=true

      elif [[ $response == $no_response ]]; then
        echo
        echo "IMPORTANT! The onboard wireless will **NOT** change / stay enabled."
        echo "IMPORTANT! You may want to take note of this."
        is_done=true
      else
        clear
        echo
        echo $PROMPT_SPACER
        echo $PROMPT_SPACER
        echo $PROMPT_SPACER
        echo "WARNING!"
        echo "WARNING: you gave invalid input."
        echo "WARNING: you must enter 'y' or 'n'."
        echo
      fi
    done
  }


  # prompt the user to enable the rpi3 onboard wireless card
  function prompt_enable_wireless(){
    local -r yes_response="y"
    local -r no_response="n"
    local is_done=false
    local response=""

    while [ $is_done == false ]; do
      echo "It looks this machine is a Raspberry Pi 3."
      echo "Would you like to enable the **ONBOARD** wireless network interface? (y/n)"
      echo "WARNING: this will reboot your Raspberry Pi 3 automatically"

      read response

      if [[ $response == $yes_response ]]; then
        echo
        echo "IMPORTANT! The onboard wireless will be enabled."
        echo "IMPORTANT! You may want to take note of this."
        echo "IMPORTANT! TO RUN INTERFACE CONFIGURATION AGAIN USE THE FLAG --modify-interface"

        unblacklist_wireless_card

        is_done=true

      elif [[ $response == $no_response ]]; then
        echo
        echo "IMPORTANT! The onboard wireless will **NOT** change / stay disabled."
        echo "IMPORTANT! You may want to take note of this."
        is_done=true
      else
        clear
        echo
        echo $PROMPT_SPACER
        echo $PROMPT_SPACER
        echo $PROMPT_SPACER
        echo "WARNING!"
        echo "WARNING: you gave invalid input."
        echo "WARNING: you must enter 'y' or 'n'."
        echo
      fi
    done
  }


  # determines if the user should be prompted to enable the card or disable it
  function prompt(){
    # is on or off?
    if [[ $(cat "$BLACKLIST_FILE" | grep "$DISABLED_WIRELESS_WRAPPER_STRING") ]]; then
      # IS CURRENTLY ENABLED
      prompt_enable_wireless
      
    else
      #IS CURRENT DISABLED
      prompt_disable_wireless
    fi
  }


  # ########################################
  # ########################################
  function main(){
    # > get config info from the ims
    # > then restart the agent process
    log "RUNNING RPI3 INITIALIZATION"
    echo "RUNNING INTERFACE SETUP FOR RASPBERRY PI 3"

    clear
    echo
    echo $PROMPT_SPACER
    echo $PROMPT_SPACER
    echo $PROMPT_SPACER
    echo "YOUR INPUT IS REQUIRED!"

    prompt

    echo $PROMPT_SPACER
    echo $PROMPT_SPACER
    echo $PROMPT_SPACER
    echo $PROMPT_SPACER
    echo  

  }
  # ########################################
  # ########################################
  main
)



function dev_flag_warning(){
  log "$PROMPT_SPACER"
  log "$PROMPT_SPACER"
  log "$PROMPT_SPACER"
  log "RUNNING IN DEV MODE -- RUNNING IN DEV MODE -- RUNNING IN DEV MODE -- RUNNING IN DEV MODE"
  log "$PROMPT_SPACER"
  log "$PROMPT_SPACER"
  log "$PROMPT_SPACER"
}

function blacklist_changed_warning(){
  echo_and_log "DETECTED HARDWARE CHANGE: RASPBERRY PI 3, wireless interface change"
  echo_and_log "THIS MACHINE IS GOING DOWN **IMMEDIATELY** FOR A REBOOT TO CONFIGURE THE WIRELESS CARD PROPERLY"
  log "the reboot will implicitly pick up the new configuration"
}



# ###################################################################################################################################################
# ###################################################################################################################################################
# ###################################################################################################################################################
# MAIN # ############################################################################################################################################
# ###################################################################################################################################################
# ###################################################################################################################################################
# ###################################################################################################################################################
function main(){
  initialize_input $ARGS;
  # NOTE: THE check_input FUNCTION WILL EXIT THE SCRIPT IMMEDIATELY IF IT DETECTS SOMETHING WRONG WITH THE INPUT
  check_input # <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
  # NOTE: THE check_input FUNCTION WILL EXIT THE SCRIPT IMMEDIATELY IF IT DETECTS SOMETHING WRONG WITH THE INPUT

  print_machine_information
  
  echo_and_log "STARTING THE AGENT SETUP SCRIPT!"
  

  if [[ "$IS_DEV" == "true" ]]; then
    dev_flag_warning
  fi

  if   [[ "$IS_INTERFACE_SETUP" == "true" && $(is_rpi_3_agent) == "true"  ]]; then
    module::initialize_rpi_3
    exit 0
  elif [[ "$IS_INTERFACE_SETUP" == "true" && $(is_rpi_3_agent) == "false" ]]; then
    echo_and_log "THIS IS NOT AN RPI3: cannot modify wireless interface"
    usage
    exit 1
  fi
  
  
  if [[ "$IS_INSTALL_AGENT_SOFTWARE" == "true" && $(is_software_agent) == "true" ]]; then    
    module::initialize_software_agent
  else
    echo_and_log "THIS IS NOT A SOFTWARE AGENT: cannot install Netbeez software packages"
    usage
    exit 1
  fi
  
  
  if [[ "$IS_FETCH_IMS_CONFIG" == "true" ]]; then
    module::fetch_ims_configuration
  fi
    


  # IF THE WIRELESS INTERFACE (for rpi3 only) WAS CHANGED - REBOOT
  if [[ $(is_blacklist_changed) == "true" ]]; then
    blacklist_changed_warning
    sudo reboot
  else
    # restart the agent processes to use the new configuration
    restart_agent_process
    echo_and_log "THIS SCRIPT IS COMPLETE"
  fi

  
}
main;


# ###################################################################################################################################################
# ###################################################################################################################################################
# ###################################################################################################################################################
# ###################################################################################################################################################
# ###################################################################################################################################################
# ###################################################################################################################################################
# ###################################################################################################################################################









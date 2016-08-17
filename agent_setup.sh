#!/bin/bash

# Netbeez
# Sets an Agent up to communicate with a Dashboard
# Agent -> request config -> central server -> config -> Agent
# find <<<MAIN>>> at the bottom of the file

set -e #exit all shells if script fails

# #########
# GLOBAL CONSTANTS
# #########
readonly ERROR=1
readonly PASS=0
readonly PROGRAM="$0"
readonly CONFIG_FOLDER="/etc/netbeez"
readonly CONFIG_FILE="netbeez-agent.conf"
SECRET=""
IS_DEBIAN=false
IS_IMAGE=false
IS_HELP=false


# PARSE PARAMS
TEMP=`getopt -o dish --long ,debian,image,secret:,help -- "$@"`
# TEMP=`getopt -o --long ,debian,image,secret:,help -- "$@"`
eval set -- "$TEMP"
while true ; do
    case "$1" in
        --debian)
            IS_DEBIAN=true;
            shift 1
            ;;
        --image)
            IS_IMAGE=true;
            shift 1
            ;;
        --secret) 
            SECRET=$2;
            shift 2
            ;;
        --help)
            IS_HELP=true
            shift 1
            ;;
        *)
            break
            ;;
    esac
done;
readonly IS_DEBIAN
readonly IS_IMAGE
readonly SECRET
readonly HELP

# #########
# GLOBAL FUNCTIONS
# #########
# LOGGING
log(){
  local msg="$1"
  echo "$msg"
}

error(){
  local msg="$1"
  log "ERROR: $msg"
}

error_exit(){
  local msg="$1"
  error "EXITING SCRIPT: $msg"
  error "EXITING SCRIPT: If you're stuck, contact support@netbeez.net"
  exit "$ERROR"
}


# ############################################
# ############################################
# SELF CONFIGURE
# ############################################
# ############################################
# the agent will configure itself from the ims
_self_configure()(
  # GLOBALS
  readonly AGENT_PEM_FILE="netbeez-agent.pem"
  readonly URL="https://ims.netbeez.net/"
  # readonly URL="https://192.168.33.8/"
  readonly END_POINT="apis/v1/agent_setup"
  readonly IMS_URL="$URL$END_POINT"



  # #########
  # FUNCTIONS
  # #########
  # HELPERS
  find_value_by_key(){
    # ###################
    # awk sets RS and FS so that 'k1:v1,...,kn:vn' is
    # "formatted" into a 2D table
    # then matches the key/$1 and prints value/$2
    # ###################
    local key="$1"
    local json="$2"

    printf "$json" | awk -v key="\"$key\"" 'BEGIN{ RS=","; FS=":"; }; $1 ~ key {print $2}' | sed 's/"//g'
  }

  replace_value_by_key(){
    # replaces a value associated with a key
    # for example, foo:bar maybe become foo:rab
    local key="$1"
    local new_value="$2"
    local json="$3"

    cat "$json" | perl -pe "s/\"host\":\".*?\",/\"host\":\"$new_value\",/g"
  }

  write_to_disk(){
    # writes data to disk
    local data="$1"
    local location="$2"
    bash -c "echo \"$data\" > \"$location\""
  }

  verify_md5(){
    # this verifies md5s for a file on disk
    # > create new md5: new_md5 = md5(file_on_disk)
    # > then compare: new_md5 == given_md5
    local check_me="$1"
    local given_md5=$(echo "$2" | cut -d' ' -f1)
    local new_md5=$(md5sum "$check_me" | cut -d' ' -f1)
    # new_md5="hello wrold" #this is used to test failed md5s
    # echo "$new_md5"
    # echo "$given_md5"
    local result=$(echo "$given_md5" | grep "$new_md5")
    # echo "$result"
    if [[ "$result" == "" ]]; then
      echo "$ERROR"
    else
      echo "$PASS"
    fi
  }

  process_agent_pem(){
    # 1. writes agent_pem to disk
    # 2. verifies the integrity of agent_pem
    # 3. moves agent_pem to proper location
    local netbeez_agent_pem="$1"
    local netbeez_agent_pem_md5="$2"

    log "VERIFYING key integrity"
    # echo $netbeez_agent_pem
    write_to_disk "$netbeez_agent_pem" "$AGENT_PEM_FILE"
    # printf "$netbeez_agent_pem_md5"
    local is_okay=$(verify_md5 "$AGENT_PEM_FILE" "$netbeez_agent_pem_md5")
    if [[ "$is_okay" == "$PASS" ]]; then
      mkdir -p "$CONFIG_FOLDER"
      mv "$AGENT_PEM_FILE" "$CONFIG_FOLDER/$AGENT_PEM_FILE"
    else
      error_exit "THE key could not be verified"
    fi
  }

  request_config_data(){
    #get config data from the ims
    echo $(curl --silent \
                --request POST "$IMS_URL" \
                --insecure \
                --data "secret=$SECRET" \
                | sed 's/{\|}//g')
  }

  check_result(){
    # if any of parsed server values are empty, then something went wrong
    # if we have a message from the server then it at least got that far
    local result="$1"
    local server_message="$2"
    if [[ "$result" == "" && "$server_message" == "" ]]; then
      error_exit "UNKNOWN ERROR: something went wrong with the request. Please try again."
    elif [[ "$result" == "" ]]; then
      error_exit "$server_message"
    fi
  }

  check_required_files(){
    if [[ ! -f "$CONFIG_FOLDER/$CONFIG_FILE" ]]; then
      error_exit "CONFIG file ($CONFIG_FOLDER/$CONFIG_FILE) does not exist. Something went wrong during the installation."
    else
      cp "$CONFIG_FOLDER/$CONFIG_FILE" "$CONFIG_FOLDER/$CONFIG_FILE.bak"
    fi
  }

  update_config_file(){
    #ex. {"host":"hostname.netbeezcloud.net", "secure_port":"20018", "interfaces":"eth0", "model":"software-debian"}
    local host="$1"
    local secure_port="$2"
    local interface="$3"
    # parse model from current config file
    local config_data=$(cat "$CONFIG_FOLDER/$CONFIG_FILE" | sed 's/{\|}//g')
    local model=$(find_value_by_key "model" "$config_data")
    # create config file
    local config='{\"host\":\"'"$host"'\", \"secure_port\":\"'"$secure_port"'\", \"interfaces\":\"'"$interface"'\", \"model\":\"'"$model"'\"}'
    # write it
    write_to_disk "$config" "$CONFIG_FOLDER/$CONFIG_FILE"
  }


  # ########################################
  main_self_configure(){
    # this function will self configure an agent
    # from info contained on the IMS
    log "BEGINNING to self-configure this agent"
    # does the required config file exist
    check_required_files
    # REQUEST DATA
    ims_config=$(request_config_data)
    # PARSE DATA
    local host=$(find_value_by_key "host" "$ims_config")
    local secure_port=$(find_value_by_key "secure_port" "$ims_config")
    local interface=$(find_value_by_key "interface" "$ims_config")
    # local model=$(find_value_by_key "model" "$ims_config")
    local netbeez_agent_pem=$(find_value_by_key "netbeez_agent_pem" "$ims_config")
    local netbeez_agent_pem_md5=$(find_value_by_key "netbeez_agent_pem_md5" "$ims_config")
    local server_message=$(find_value_by_key "msg" "$ims_config")

    # log "SERVER MESSAGE: $server_message"
    # CHECK RESULTS
    check_result "$host" "$server_message"
    check_result "$secure_port" "$server_message"
    check_result "$netbeez_agent_pem" "$server_message"
    check_result "$netbeez_agent_pem_md5" "$server_message"
    check_result "$server_message" "$server_message"
    
    # VERIFY KEY
    process_agent_pem "$netbeez_agent_pem" "$netbeez_agent_pem_md5"
    # update_host "$host"
    update_config_file "$host" "$secure_port" "$interface"
  }
  main_self_configure
  # ########################################
)







# ############################################
# ############################################
# SOFTWARE AGENT CONFIGURE
# ############################################
# ############################################
_software_agent()(
  # https://netbeez.zendesk.com/hc/en-us/articles/207989403-Install-NetBeez-agents-All-versions-
  # #########
  # FUNCTIONS
  # #########
  file_check(){
    #if the file exists
    if [ -f "$CONFIG_FOLDER/$CONFIG_FILE" ]; then
      error_exit "Configuration file ($CONFIG_FOLDER/$CONFIG_FILE) detected. Maybe you wanted to use '--image' instead of '--debian'."
    fi

  }

  add_repos(){
    # Add the NetBeez software repository, update the database, and install the netbeez-agent package:
    log "ADDING netbeez repos and installing netbeez software"
    echo "deb http://repo.netbeez.net wheezy main" | \
      tee -a /etc/apt/sources.list
    wget -O - http://repo.netbeez.net/netbeez_pub.key | \
      apt-key add -
    apt-get update
    apt-get install netbeez-agent -y
  }

  restart_agent_process(){
    # Restart the agent process
    log "RESTARTING agent process"
    service netbeez-agent stop
    service netbeez-agent start
  }

  # ########################################
  main_software_agent(){
    # this function will add netbeez repos
    # > get config info from the ims
    # > then restart the agent process
    file_check
    add_repos
    _self_configure
    restart_agent_process
  }
  main_software_agent
  # ########################################
)








# ############################################
# ############################################
# RPI AND VIRTUAL AGENT CONFIG
# ############################################
# ############################################
_rpi_and_virtual_agent()(
  # https://netbeez.zendesk.com/hc/en-us/articles/207989403-Install-NetBeez-agents-All-versions-
  # #########
  # FUNCTIONS
  # #########
  restart_agent_process(){
    # Restart the agent process
    log "RESTARTING agent process"
    service nbagent_prod stop
    service nbagent_prod start
  }

  # ########################################
  main_rpi_virtual_agent(){
    # > get config info from the ims
    # > then restart the agent process
    _self_configure
    restart_agent_process
  }
  main_rpi_virtual_agent
  # ########################################
)





# ############################################
# ############################################
# ############################################
# ############################################
# ############################################
usage(){
  echo "----------------------------------------------------------------------------------------------------"
  # echo "Usage: $PROGRAM ( (--debian | -d) | (--image | -i) ) ( --secret <key_string> | -s <key_string> ) [--help | -h]"
  echo "Usage: $PROGRAM --secret=<key> (--debian | --image)  [--help]"
  echo "Options: "
  echo "       --debian          set up a debian instance (aka software agent)"
  echo "                         > REQUIRED: --debian OR --image"
  echo "       --image           set up an image instance (aka raspberry pi or virtual agent)"
  echo "                         > REQUIRED: --debian OR --image"
  echo "       --secret=<key>    the secret key given to you from Netbeez (usually via email)"
  echo "                                    > REQUIRED"
  echo "       --help            displays this usage page"
  echo ""
  echo "       Good Example: $PROGRAM --debian --secret \"DF756KH3R39824FKLH45608GH23F7GIU3H2F80H\""
  echo "       BAD Example:  $PROGRAM --debian --image    "
  echo "                      (mutually exclusive parameters used: --debian and --image; missing --secret)"
  echo ""
  echo "       More info: https://netbeez.zendesk.com/hc/en-us/articles/207989403-Install-NetBeez-agents-All-versions-"
  echo "----------------------------------------------------------------------------------------------------"

}


check_input(){
  # checks parsed parameters
  # if any of the parameter options are 
  # > invalid a usage will be displayed
  local is_usage=false
  local msg=""
  local exit_status="$ERROR"

  echo ""
  if [[ "$IS_HELP" == true ]]; then
    is_usage=true
    exit_status="$PASS"
  fi

  if [[ "$SECRET" == "" ]]; then
    log "SECRET cannot be empty"
    is_usage=true
  fi

  if [[ "$IS_DEBIAN" == true  && "$IS_IMAGE" == true  ]]; then
    log "CONFLICTING parameters were given"
    is_usage=true

  fi
  
  if [[ "$IS_DEBIAN" == false  && "$IS_IMAGE" == false ]]; then
    log "REQUIRED parameters were not given"
    is_usage=true
  fi


  if [[ "$is_usage" == true ]]; then
    usage
    exit "$exit_status"
  fi
}


# MAIN >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
main(){
  check_input
  # checks flags to determine which module to config with
  if   [[ "$IS_DEBIAN" == true ]]; then
    log "DEBIAN flag: configuring as software agent"
    _software_agent
  elif [[ "$IS_IMAGE" == true  ]]; then
    log "RPI or VIRTUAL flag: configuring as software agent"
    _rpi_and_virtual_agent
  fi
}
main
# ############################################
# ############################################
# ############################################
# ############################################
# ############################################
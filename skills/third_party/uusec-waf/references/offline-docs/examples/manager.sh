#!/bin/bash

info() {
	echo -e "\033[32m[UUSEC WAF] $*\033[0m"
}

warning() {
	echo -e "\033[33m[UUSEC WAF] $*\033[0m"
}

abort() {
	echo -e "\033[31m[UUSEC WAF] $*\033[0m"
	exit 1
}

if [ -z "$BASH" ]; then
	abort "Please execute this script using bash and refer to the latest official technical documentation https://www.uusec.com/"
fi

if [ "$EUID" -ne "0" ]; then
	abort "Please run with root privileges"
fi

SCRIPT_PATH="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd  "$SCRIPT_PATH"

if [ ! $(command -v docker) ]; then
	warning "Docker Engine not detected, we will automatically install it for you. The process is slow, please be patient ..."
	sh install-docker.sh
	if [ $? -ne "0" ]; then
		abort "Automatic installation of Docker Engine failed. Please manually install it before executing this script"
	fi
	systemctl enable docker && systemctl daemon-reload && systemctl restart docker
fi

DC_CMD="docker compose"
$DC_CMD version > /dev/null 2>&1
if [ $? -ne "0" ]; then
	abort "Your Docker version is too low and lacks the 'docker compose' command. Please uninstall and install the latest version"
fi

if [ ! -f ".env" ];then
	echo "MYSQL_PASSWORD=$(LC_ALL=C tr -dc A-Za-z0-9 </dev/urandom | head -c 32)" > .env
fi

stop_waf(){
	$DC_CMD down
}

uninstall_waf(){
	stop_waf
	docker rm -f uuwaf wafdb > /dev/null 2>&1
	docker network rm wafnet > /dev/null 2>&1
	docker images|grep uuwaf|awk '{print $3}'|xargs docker rmi -f > /dev/null 2>&1
	docker volume ls|grep _waf_|awk '{print $2}'|xargs docker volume rm -f > /dev/null 2>&1
}

start_waf(){
	if [ ! $(command -v netstat) ]; then
		$( command -v yum || command -v apt-get || command -v zypper ) -y install net-tools
	fi
	port_status=`netstat -nlt|grep -E ':(80|443|777|4443|4447)\s'|wc -l`
	if [ $port_status -gt 0 ]; then
		abort "One or more of ports 80, 443, 777, 4443, 4447 are occupied. Please shutdown the corresponding service or modify its port"
	fi
	$DC_CMD up -d --remove-orphans
}

upgrade_waf(){
	curl https://uuwaf.uusec.com/docker-compose.yml -o docker-compose.yml
	$DC_CMD pull
	$DC_CMD up -d --remove-orphans
}

repair_waf(){
	if [ $(command -v firewall-cmd) ]; then
		systemctl restart firewalld > /dev/null 2>&1
	elif [ $(command -v ufw) ]; then
		systemctl restart ufw > /dev/null 2>&1
	fi
	systemctl daemon-reload
	systemctl restart docker
}

restart_waf(){
	stop_waf
	start_waf
}

start_menu(){
    clear
    echo "========================="
    echo "UUSEC WAF Management"
    echo "========================="
    echo "1. Start"
    echo "2. Stop"
    echo "3. Restart"
    echo "4. Upgrade"
    echo "5. Repair"
    echo "6. Uninstall"
    echo "7. Exit"
    echo
    read -p "Please enter the number: " num
    case "$num" in
	1)
	start_waf
	info "Startup completed"
	;;
	2)
	stop_waf
	info "Stop completed"
	;;
	3)
	restart_waf
	info "Restart completed"
	;;
	4)
	upgrade_waf
	info "Upgrade completed"
	;;
	5)
	repair_waf
	info "Repair completed"
	;;
	6)
	uninstall_waf
	info "Uninstall completed"
	;;
	7)
	exit 1
	;;
	*)
	clear
	info "Please enter the right number"
	;;
    esac
    sleep 3s
    start_menu
}

start_menu

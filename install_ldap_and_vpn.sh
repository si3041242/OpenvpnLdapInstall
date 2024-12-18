#!/bin/bash

# 定义颜色变量
RED="\033[31m"      
GREEN="\033[32m"    
YELLOW="\033[33m"   
BLUE="\033[34m"     
RES="\033[0m"       

# 定义基础变量
LDAP_PASSWORD="A9gPV5MT2xm92yAALo"
DC1="gems"
DC2="vip"
DOMAIN="$DC1.$DC2"
LOCAL_IP=$(hostname -I | awk '{print $1}')
VPN="vpn"
VPNC_CONF="${VPN}.conf"
LDAP_VPN_Auth="/etc/openvpn/auth/ldap.conf"
VPN_WorkDir="/opt/vpn-worker"
# 测试用户
username=test

# 定义日志函数
log_info() {
    echo -e "${GREEN}[信息] $1${RES}"
}

log_warn() {
    echo -e "${YELLOW}[警告] $1${RES}"
}

log_error() {
    echo -e "${RED}[错误] $1${RES}"
}

# 检查root权限
check_root() {
    if [ $EUID -ne 0 ]; then
        log_error "此脚本必须以root用户运行"
        exit 1
    fi
}

# 安装所需软件包
install_packages() {
    log_info "开始安装必要的软件包..."
    apt-get update -y || {
        log_error "更新软件源失败"
        exit 1
    }
    
    # 安装 OpenVPN 相关包
    apt-get install -y openvpn easy-rsa libssl-dev openssl openvpn-auth-ldap || {
        log_error "OpenVPN 相关软件包安装失败"
        exit 1
    }
    
    # 安装 LDAP 相关包
    DEBIAN_FRONTEND=noninteractive apt-get install -y slapd ldap-utils || {
        log_error "LDAP 相关软件包安装失败"
        exit 1
    }
    
    log_info "所有软件包安装完成"
}

# 初始化 LDAP
setup_ldap() {
    log_info "配置 LDAP..."

    # 预配置 slapd
    local debconf_settings=(
        "slapd slapd/password1 password $LDAP_PASSWORD"
        "slapd slapd/password2 password $LDAP_PASSWORD"
        "slapd slapd/internal/adminpw password $LDAP_PASSWORD"
        "slapd slapd/internal/generated_adminpw password $LDAP_PASSWORD"
        "slapd slapd/domain string $DOMAIN"
        "slapd shared/organization string $DOMAIN"
        "slapd slapd/backend select MDB"
        "slapd slapd/purge_database boolean true"
        "slapd slapd/move_old_database boolean true"
        "slapd slapd/allow_ldap_v2 boolean false"
        "slapd slapd/no_configuration boolean false"
    )
    
    for setting in "${debconf_settings[@]}"; do
        echo "$setting" | debconf-set-selections
    done

    # 配置 schema
    configure_ldap_schema
    
    # 创建基础结构
    create_ldap_base
    
    # 创建测试用户
    create_ldap_test_user
}

# 配置 LDAP Schema
configure_ldap_schema() {
    # 备份并修改 schema 文件
    cp /etc/ldap/schema/inetorgperson.schema /etc/ldap/schema/inetorgperson.schema.bak || {
        log_error "备份 schema 文件失败"
        exit 1
    }

    log_info "添加 privilege 属性..."
    # 添加 privilege 属性
    sed -i '/attributetype ( 2.16.840.1.113730.3.1.216/i \
attributetype ( 2.16.840.1.113730.3.1.800\
        NAME '\''privilege'\''\
        DESC '\''privilege'\''\
        EQUALITY caseIgnoreMatch\
        SUBSTR caseIgnoreSubstringsMatch\
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )' /etc/ldap/schema/inetorgperson.schema

    # 修改 objectclass
    sed -i 's/userSMIMECertificate $ userPKCS12 )/userSMIMECertificate $ userPKCS12 $ privilege )/' /etc/ldap/schema/inetorgperson.schema

    create_slapd_conf
    rebuild_slapd_config
}

# 创建 LDAP 基础结构
create_ldap_base() {
    log_info "创建 LDAP 基础结构..."
    
    # 创建基础域和组织单元
    cat > base.ldif << EOF
# 创建域
dn: dc=${DC1},dc=${DC2}
objectClass: dcObject
objectClass: organization
dc: ${DC1}
o: ${DOMAIN}

# 创建组织单元
dn: ou=${DC1},dc=${DC1},dc=${DC2}
objectClass: organizationalUnit
objectClass: top
ou: ${DC1}
EOF

    ldapadd -x -D "cn=admin,dc=${DC1},dc=${DC2}" -w "${LDAP_PASSWORD}" -f base.ldif || {
        log_error "创建 LDAP 基础结构失败"
        return 1
    }
    
    log_info "LDAP 基础结构创建成功（默认 OU 是 ${DC1}，如需其他 OU 请手动添加）"
}

# 创建 slapd.conf
create_slapd_conf() {
    cat > /etc/ldap/slapd.conf << EOF
include         /etc/ldap/schema/core.schema
include         /etc/ldap/schema/cosine.schema
include         /etc/ldap/schema/nis.schema
include         /etc/ldap/schema/inetorgperson.schema
include         /etc/ldap/schema/openldap.schema
include         /etc/ldap/schema/dyngroup.schema

pidfile         /var/run/slapd/slapd.pid
argsfile        /var/run/slapd/slapd.args

modulepath      /usr/lib/ldap
moduleload      back_mdb
moduleload      ppolicy
moduleload      dynlist

loglevel        none
sizelimit 500
tool-threads 1

backend mdb
database mdb
suffix "dc=$DC1,dc=$DC2"
rootdn "cn=admin,dc=$DC1,dc=$DC2"
rootpw $LDAP_PASSWORD

index   objectClass eq
directory "/var/lib/ldap"

access to attrs=userPassword
    by self write
    by anonymous auth
    by * none
access to *
    by * read
EOF

    # 更新 ldap.conf
    cat > /etc/ldap/ldap.conf << EOF
BASE dc=$DC1,dc=$DC2
URI ldap://$LOCAL_IP
EOF
}

# 重建 slapd 配置
rebuild_slapd_config() {
    cd /etc/ldap
    if [ -d "slapd.d" ]; then
        cp -a slapd.d slapd.bak
        rm -rf slapd.d/*
    else
        mkdir slapd.d
    fi

    slaptest -f slapd.conf -F /etc/ldap/slapd.d/ || {
        log_error "LDAP 配置测试失败"
        [ -d "slapd.bak" ] && cp -a slapd.bak/* slapd.d/
        exit 1
    }

    chown -R openldap:openldap slapd.d
    systemctl restart slapd
}

# 创建 LDAP 测试用户
create_ldap_test_user() {
    log_info "创建 LDAP 测试用户..."
    
    tee test_user.ldif << EOF
dn: uid=testuser,dc=$DC1,dc=$DC2
objectClass: inetOrgPerson
objectClass: top
cn: Test User
sn: User
uid: testuser
mail: test@example.com
privilege: vpn-test
userPassword: testpass
EOF

    ldapadd -x -D "cn=admin,dc=$DC1,dc=$DC2" -w "$LDAP_PASSWORD" -f test_user.ldif
    ldapsearch -x -D "cn=admin,dc=$DC1,dc=$DC2" -w "$LDAP_PASSWORD" -b "dc=$DC1,dc=$DC2"
}

# 初始化 OpenVPN
setup_openvpn() {
    log_info "初始化 OpenVPN..."
    init_cert_env
    create_server_cert
    setup_vpn_keys
    backup_easyrsa
    setup_client_env
    create_client_cert
    configure_openvpn
    configure_vpn_network
}

# 初始化证书环境
init_cert_env() {
    mkdir -p /etc/openvpn/easy-rsa
    cp -a /usr/share/easy-rsa/* /etc/openvpn/easy-rsa/
    cd /etc/openvpn/easy-rsa/

# 创建或修改 vars 文件
    cat > vars << EOF
# 证书有效期（设置为10年 = 3650天）

# CA 设置
export EASYRSA_CA_EXPIRE="3650"
export EASYRSA_CERT_EXPIRE="3650"
export EASYRSA_CRL_DAYS="3650"
EOF

    # 设置适当的权限
    chmod 700 /etc/openvpn/easy-rsa
    chmod 600 vars
}

# 创建服务器证书
create_server_cert() {
    cd /etc/openvpn/easy-rsa/
    
    # 加载变量
    source vars
    ./easyrsa init-pki
    yes "" | ./easyrsa build-ca nopass
    yes "" | ./easyrsa gen-req server nopass
    yes "yes" | ./easyrsa sign server server
    ./easyrsa gen-dh
}

# 创建客户端证书
create_client_cert() {
    local username=username
    cd ${VPN_WorkDir}

    # 设置环境变量确保正确的 CN
    export EASYRSA_REQ_CN="$username"
    export EASYRSA_BATCH=1

    if [ ! -f "pki/issued/${username}.crt" ]; then
        # 生成客户端密钥和请求
        ./easyrsa gen-req "$username" nopass
        
        # 签名客户端证书
        ./easyrsa sign-req client "$username"
        
        # 验证证书
        if [ -f "pki/issued/${username}.crt" ]; then
            log_info "证书生成成功: $username"
            # 验证 CN 是否正确
            openssl x509 -in "pki/issued/${username}.crt" -noout -subject | grep "CN = ${username}" || {
                log_warn "证书 CN 验证失败"
            }
        else
            log_error "证书生成失败: $username"
            return 1
        fi
    else
        log_warn "证书已存在: $username"
    fi
}

# 设置 VPN 密钥和目录
setup_vpn_keys() {
    mkdir -p /etc/openvpn/{server,conf,auth,status}
    openvpn --genkey --secret /etc/openvpn/server/ta.key
    
    cd /etc/openvpn/server
    cp /etc/openvpn/easy-rsa/pki/{dh.pem,ca.crt} .
    cp /etc/openvpn/easy-rsa/pki/issued/server.crt .
    cp /etc/openvpn/easy-rsa/pki/private/server.key .
}

# 备份 Easy-RSA
backup_easyrsa() {
    cd /etc/openvpn/easy-rsa
    tar zcf /etc/openvpn/openvpn-easy-rsa.tar.gz ./
}

# 设置客户端环境
setup_client_env() {
    mkdir -p ${VPN_WorkDir}
    cp -a /etc/openvpn/easy-rsa/* ${VPN_WorkDir}
    cd ${VPN_WorkDir}
    mkdir -p server-cert
    cp /etc/openvpn/server/{ca.crt,ta.key} server-cert/

    create_client_template
    create_client_script
}

# 创建客户端证书
create_client_cert() {
    cd ${VPN_WorkDir}
    
    if [ ! -f "pki/issued/test.crt" ]; then
        yes "" | ./easyrsa gen-req test nopass
        yes "yes" | ./easyrsa sign client test
    fi
}

# 创建客户端配置模板
create_client_template() {
    Internet_IP=$(curl -s ip.sb) || {
        log_error "获取公网 IP 失败"
        exit 1
    }
    
    tee client.template << EOF
client
dev tun
proto udp
remote ${Internet_IP} 21194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-CBC
auth SHA256
auth-user-pass
auth-nocache
key-direction 1
verb 3
EOF
}

# 创建客户端配置生成脚本
create_client_script() {
    cat > make_config.sh << 'EOF'
#!/bin/bash
OUTPUT_DIR="clients/$1"
BASE_CONFIG="client.template"
mkdir -p "$OUTPUT_DIR"
cat ${BASE_CONFIG} \
    <(echo -e '<ca>') \
    server-cert/ca.crt \
    <(echo -e '</ca>\n<cert>') \
    "pki/issued/$1.crt" \
    <(echo -e '</cert>\n<key>') \
    "pki/private/$1.key" \
    <(echo -e '</key>\n<tls-auth>') \
    server-cert/ta.key \
    <(echo -e '</tls-auth>') \
    > "${OUTPUT_DIR}/${1}.ovpn"
EOF
    chmod +x make_config.sh
}

# 配置 OpenVPN
configure_openvpn() {
    log_info "生成 OpenVPN 配置文件..."
    mkdir -p /etc/openvpn/auth
    tee /etc/openvpn/${VPNC_CONF} << EOF
plugin /usr/lib/openvpn/openvpn-auth-ldap.so "/etc/openvpn/auth/ldap.conf"
port 21194
proto udp
dev tun
user nobody
group nogroup
persist-key
persist-tun
duplicate-cn
ca server/ca.crt
cert server/server.crt
key server/server.key
dh server/dh.pem
tls-auth server/ta.key 0
cipher AES-256-CBC
auth SHA256
server 192.168.211.0 255.255.255.0
push "dhcp-option DNS 10.10.10.10"
push "route 10.0.0.0  255.0.0.0"
keepalive 10 120
ifconfig-pool-persist /etc/openvpn/conf/ipp_ops.txt
status /etc/openvpn/status/ops.log
log-append  /var/log/openvpn/ops.log
verb 3
explicit-exit-notify 1
EOF

    generate_ldap_vpn_auth
}

# 生成 LDAP 认证配置
generate_ldap_vpn_auth() {
    mkdir -p $(dirname ${LDAP_VPN_Auth})
    
    tee ${LDAP_VPN_Auth} << EOF
<LDAP>
        URL             ldap://${LOCAL_IP}:389
        BindDN          cn=admin,dc=${DC1},dc=${DC2}
        Password        ${LDAP_PASSWORD}
        Timeout         15
        TLSEnable       no
        FollowReferrals no
</LDAP>

<Authorization>
        BaseDN          "dc=${DC1},dc=${DC2}"
        #SearchFilter    "(&(privilege=vpn)(uid=%u))"
        SearchFilter    "uid=%u"
        RequireGroup    false
</Authorization>
EOF
}
start_openvpn() {
    log_info "启动 OpenVPN..."
    
    # 检查配置文件是否存在
    if [ ! -f "/etc/openvpn/${VPNC_CONF}" ]; then
        log_error "OpenVPN 配置文件不存在"
        return 1
    fi
    # 启动服务
    systemctl start openvpn@${VPN}.service || {
        log_error "OpenVPN 服务启动失败"
        return 1
    }

    # 检查服务状态
    if systemctl is-active --quiet openvpn@${VPN}.service; then
        log_info "OpenVPN 服务启动成功"
    else
        log_error "OpenVPN 服务启动失败"
        return 1
    fi
}

# 配置网络
configure_vpn_network() {
    log_info "配置网络规则..."
    vpn_cidr=$(awk '/server [0-9]/{print $2}' /etc/openvpn/${VPNC_CONF})
    iptables -A POSTROUTING -s $vpn_cidr/24 -d 0.0.0.0/0 -j MASQUERADE -t nat
    echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
    sysctl -p
}
# 安装和配置 Mutt
setup_mutt() {
    log_info "安装 Mutt 邮件客户端..."
    
    apt-get install -y mutt || {
        log_error "Mutt 安装失败"
        return 1
    }

    # 创建示例配置
    cat > mutt_config_example << EOF
# Mutt 配置示例 (~/.muttrc)
set from = "your-email@gmail.com"
set realname = "VPN Admin"
set smtp_url = "smtps://your-email@gmail.com@smtp.gmail.com:465/"
set smtp_pass = "your-app-password"
set ssl_force_tls = yes

# Gmail 需要使用应用专用密码
# 获取方式：Google账号 -> 安全性 -> 2步验证 -> 应用专用密码
EOF

    log_info "Mutt 安装完成！"
    log_info "请按照以下步骤配置 Mutt："
    echo "1. 编辑配置文件: vim ~/.muttrc"
    echo "2. 参考示例配置: $(pwd)/mutt_config_example"
    echo "3. 如果使用 Gmail，需要设置应用专用密码,参考 https://www.laifa.xin/101-guge-gmailyouxiang-google-personal-email/"
}

# 卸载所有组件
uninstall_all() {
   log_info "开始清理 OpenVPN 和 LDAP..."
   
   # 停止服务
   systemctl stop openvpn@${VPNC_CONF/.conf/}.service
   systemctl stop slapd
   
   # 删除 iptables 规则
   vpn_cidr=$(awk '/server [0-9]/{print $2}' /etc/openvpn/${VPNC_CONF} 2>/dev/null)
   if [ ! -z "$vpn_cidr" ]; then
       iptables -t nat -D POSTROUTING -s $vpn_cidr/24 -d 0.0.0.0/0 -j MASQUERADE 2>/dev/null
       log_info "已删除 IPTables 规则"
   fi
   
   # 卸载软件包
   apt-get purge -y openvpn easy-rsa openvpn-auth-ldap slapd ldap-utils || log_warn "卸载软件包失败"
   apt-get autoremove -y || log_warn "自动清理失败"
   
   # 删除配置文件和目录
   local dirs_to_remove=(
       "/etc/openvpn"
       "${VPN_WorkDir}"
       "/var/log/openvpn"
       "/etc/ldap"
       "/var/lib/ldap"
       "/var/run/slapd"
       "/usr/share/slapd"
   )
   
   for dir in "${dirs_to_remove[@]}"; do
       if [ -d "$dir" ]; then
           rm -rf "$dir" && log_info "已删除目录: $dir" || log_warn "删除目录失败: $dir"
       fi
   done
   
   log_info "OpenVPN 和 LDAP 清理完成"
}

# 主函数
main() {
   check_root
   
   case "$1" in
       "delete"|"uninstall")
           uninstall_all
           ;;
       "install"|"")
           install_packages
           setup_ldap
           setup_openvpn
           start_openvpn
           setup_mutt
           log_info "OpenVPN 和 LDAP 安装配置完成！"
           log_info "LDAP管理员DN: cn=admin,dc=$DC1,dc=$DC2"
           log_info "LDAP密码: $LDAP_PASSWORD"
           log_info "测试用户: testuser"
           log_info "测试用户密码: testpass"
           ;;
       *)
           log_error "未知的命令: $1"
           echo "用法: $0 [install|delete]"
           exit 1
           ;;
   esac
}

# 执行主函数
main "$@"